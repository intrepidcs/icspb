#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <iterator>
#include <algorithm>
#include <map>
#include <set>
#include <nlohmann/json.hpp> // For JSON parsing

// Platform-specific includes for process execution
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#include <sstream>
#endif

namespace fs = std::filesystem;
using json = nlohmann::json;

// --- Configuration Struct ---
struct Config {
    fs::path proto_src_dir;
    fs::path output_dir;
    fs::path nanopb_path;
    std::string python_executable;
};

// --- Function Declarations ---
void parse_json_config_file(const fs::path& config_path, Config& config);
bool run_process(const std::vector<std::string>& command, const fs::path& working_dir, std::string& out_stdout, std::string& out_stderr);
bool compare_files(const fs::path& path1, const fs::path& path2);
std::pair<std::string, std::string> get_output_filenames(const fs::path& proto_file);
bool conditional_generate(const fs::path& proto_file, const Config& config);
void cleanup_stale_files(const std::vector<fs::path>& proto_files, const Config& config);
void remove_empty_directories(const fs::path& directory);
std::string validate_python_executable(const std::string& preferred_name);

std::string validate_python_executable(const std::string& preferred_name) {
#ifdef _WIN32
    // On Windows, try a few common variations if the preferred name doesn't have .exe
    std::vector<std::string> candidates;
    
    if (preferred_name.find(".exe") == std::string::npos) {
        candidates = {preferred_name, preferred_name + ".exe"};
    } else {
        candidates = {preferred_name};
    }
    
    // Use SearchPath to find executable in PATH - this is the Windows-native way
    for (const auto& candidate : candidates) {
        char full_path[MAX_PATH];
        if (SearchPathA(NULL, candidate.c_str(), NULL, MAX_PATH, full_path, NULL)) {
            std::cout << "[INFO] Found Python executable: " << candidate << " (at: " << full_path << ")" << std::endl;
            return candidate; // Return the short name since it's in PATH
        }
    }
    
    // If not found, throw an error with helpful message
    std::cerr << "[ERROR] Python executable not found: " << preferred_name << std::endl;
    std::cerr << "[ERROR] Please ensure Python is installed and in your PATH, or specify the full path to python.exe" << std::endl;
    std::cerr << "[ERROR] Common Python executable names: python.exe, python3.exe, py.exe" << std::endl;
    throw std::runtime_error("Python executable not found: " + preferred_name);
#else
    // On Unix-like systems, check if it's a full path first
    if (preferred_name.front() == '/' || preferred_name.find("./") == 0) {
        if (fs::exists(preferred_name) && !fs::is_directory(preferred_name)) {
            std::cout << "[INFO] Found Python executable: " << preferred_name << std::endl;
            return preferred_name;
        }
    } else {
        // Check if executable exists in PATH by searching PATH directories
        if (const char* path_env = std::getenv("PATH")) {
            std::string path_str(path_env);
            std::istringstream path_stream(path_str);
            std::string dir;
            
            while (std::getline(path_stream, dir, ':')) {
                if (!dir.empty()) {
                    fs::path candidate = fs::path(dir) / preferred_name;
                    if (fs::exists(candidate) && !fs::is_directory(candidate)) {
                        // Check if it's executable (on Unix systems)
                        if (access(candidate.c_str(), X_OK) == 0) {
                            std::cout << "[INFO] Found Python executable: " << preferred_name << " (at: " << candidate << ")" << std::endl;
                            return preferred_name;
                        }
                    }
                }
            }
        }
    }
    
    // If not found, throw an error
    std::cerr << "[ERROR] Python executable not found: " << preferred_name << std::endl;
    std::cerr << "[ERROR] Please ensure Python is installed and in your PATH, or specify the full path to python" << std::endl;
    throw std::runtime_error("Python executable not found: " + preferred_name);
#endif
}

int main(int argc, char* argv[]) {
    try {
        // --- Configuration Handling ---
        Config config; // Initialize with empty values
        
        // 1. Parse command-line arguments
        std::string config_file_path_str;
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--config" && i + 1 < argc) {
                config_file_path_str = argv[++i];
            } else if (arg == "--proto-src-dir" && i + 1 < argc) {
                config.proto_src_dir = fs::absolute(argv[++i]);
            } else if (arg == "--output-dir" && i + 1 < argc) {
                config.output_dir = fs::absolute(argv[++i]);
            } else if (arg == "--nanopb-path" && i + 1 < argc) {
                config.nanopb_path = fs::absolute(argv[++i]);
            } else if (arg == "--python-executable" && i + 1 < argc) {
                config.python_executable = argv[++i];
            }
        }

        // 2. If a config file is provided, parse it. Its values will OVERRIDE any other settings.
        if (!config_file_path_str.empty()) {
            fs::path config_file_path = fs::absolute(config_file_path_str);
            if (!fs::exists(config_file_path)) {
                std::cerr << "[ERROR] Configuration file not found: " << config_file_path << std::endl;
                return 1;
            }
            std::cout << "[INFO] Loading config file: " << config_file_path.string() << ". It will override other arguments." << std::endl;
            parse_json_config_file(config_file_path, config);
        }

        // 3. Validate that all configuration parameters are set
        std::vector<std::string> missing_params;
        if (config.proto_src_dir.empty()) missing_params.push_back("--proto-src-dir");
        if (config.output_dir.empty()) missing_params.push_back("--output-dir");
        if (config.nanopb_path.empty()) missing_params.push_back("--nanopb-path");
        if (config.python_executable.empty()) missing_params.push_back("--python-executable");

        if (!missing_params.empty()) {
            std::cerr << "[ERROR] The following required configuration parameters are missing:" << std::endl;
            for (const auto& param : missing_params) {
                std::cerr << "  " << param << std::endl;
            }
            std::cerr << "Please provide them via command-line arguments or a --config file." << std::endl;
            return 1;
        }

        // 4. Validate Python executable
        config.python_executable = validate_python_executable(config.python_executable);

        // 5. Validate paths exist
        if (!fs::exists(config.proto_src_dir)) {
            std::cerr << "[ERROR] Proto source directory not found: " << config.proto_src_dir << std::endl;
            return 1;
        }
        
        if (!fs::exists(config.nanopb_path)) {
            std::cerr << "[ERROR] Nanopb generator script not found: " << config.nanopb_path << std::endl;
            return 1;
        }


        std::cout << "[INFO] Using Proto Source Dir: " << config.proto_src_dir.string() << std::endl;
        std::cout << "[INFO] Using Output Dir: " << config.output_dir.string() << std::endl;
        std::cout << "[INFO] Using Nanopb Generator: " << config.nanopb_path.string() << std::endl;
        std::cout << "[INFO] Using Python Executable: " << config.python_executable << std::endl;

        std::vector<fs::path> proto_files;
        for (const auto& entry : fs::recursive_directory_iterator(config.proto_src_dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".proto") {
                proto_files.push_back(entry.path());
            }
        }

        if (proto_files.empty()) {
            std::cout << "[WARNING] No .proto files found in '" << config.proto_src_dir << "'. Exiting." << std::endl;
            // Still run cleanup in case all files were removed
            cleanup_stale_files(proto_files, config);
            return 0;
        }

        std::cout << "[INFO] Found " << proto_files.size() << " .proto file(s) to process." << std::endl;

        for (const auto& proto_file : proto_files) {
            if (!conditional_generate(proto_file, config)) {
                std::cerr << "[ERROR] Failed to process " << proto_file << ". Halting script." << std::endl;
                return 1;
            }
        }

        std::cout << "[INFO] All proto files processed successfully." << std::endl;

        // --- Cleanup Step ---
        cleanup_stale_files(proto_files, config);

    } catch (const std::exception& e) {
        std::cerr << "[FATAL ERROR] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

void cleanup_stale_files(const std::vector<fs::path>& proto_files, const Config& config) {
    std::cout << "[INFO] --- Starting cleanup of stale files ---" << std::endl;
    
    // 1. Build a set of all files that are expected to exist.
    std::set<fs::path> expected_files;
    for (const auto& proto_file : proto_files) {
        fs::path relative_dir_path = fs::relative(proto_file.parent_path(), config.proto_src_dir);
        auto [c_file, h_file] = get_output_filenames(proto_file);
        expected_files.insert(config.output_dir / relative_dir_path / c_file);
        expected_files.insert(config.output_dir / relative_dir_path / h_file);
    }

    // 2. Iterate through the output directory and find files to delete.
    if (fs::exists(config.output_dir)) {
        for (const auto& entry : fs::recursive_directory_iterator(config.output_dir)) {
            if (entry.is_regular_file()) {
                const auto& extension = entry.path().extension();
                if (extension == ".c" || extension == ".h") {
                    // Check if this is an expected file.
                    if (expected_files.find(entry.path()) == expected_files.end()) {
                        // If not found in the expected set, it's stale.
                        std::cout << "[INFO] Deleting stale file: " << entry.path().string() << std::endl;
                        fs::remove(entry.path());
                    }
                }
            }
        }
    }

    // 3. Clean up any directories that may now be empty.
    std::cout << "[INFO] Cleaning up empty directories..." << std::endl;
    remove_empty_directories(config.output_dir);

    std::cout << "[INFO] --- Cleanup finished ---" << std::endl;
}

void remove_empty_directories(const fs::path& directory) {
    if (!fs::exists(directory) || !fs::is_directory(directory)) {
        return;
    }
    // Post-order traversal: recurse into subdirectories first.
    for (const auto& entry : fs::directory_iterator(directory)) {
        if (fs::is_directory(entry.path())) {
            // Do not recurse into our own temp directory
            if (entry.path().filename() != ".tmp_gen") {
                remove_empty_directories(entry.path());
            }
        }
    }
    // After handling subdirectories, check if this directory is empty.
    try {
        if (fs::is_empty(directory)) {
            std::cout << "[INFO] Removing empty directory: " << directory.string() << std::endl;
            fs::remove(directory);
        }
    } catch(const fs::filesystem_error&) {
        // Suppress errors, e.g. from trying to check a just-deleted directory.
    }
}


bool conditional_generate(const fs::path& proto_file, const Config& config) {
    std::cout << "[INFO] Processing: " << proto_file.string() << std::endl;

    fs::path relative_dir_path = fs::relative(proto_file.parent_path(), config.proto_src_dir);
    fs::path relative_proto_path = fs::relative(proto_file, config.proto_src_dir);

    fs::path dest_subdir = config.output_dir / relative_dir_path;
    fs::create_directories(dest_subdir);

    fs::path local_temp_dir = config.output_dir / ".tmp_gen";
    if (fs::exists(local_temp_dir)) {
        fs::remove_all(local_temp_dir);
    }
    fs::create_directories(local_temp_dir);

    bool success = false;
    try {
        // Use proper std::filesystem path normalization
        // Create copies and normalize to platform-preferred separators
        fs::path nanopb_path_normalized = config.nanopb_path;
        fs::path output_dir_normalized = local_temp_dir;
        fs::path proto_path_normalized = relative_proto_path;
        
        nanopb_path_normalized.make_preferred();
        output_dir_normalized.make_preferred();
        proto_path_normalized.make_preferred();
        
        std::vector<std::string> command = {
            config.python_executable,
            nanopb_path_normalized.string(),
            "--output-dir=" + output_dir_normalized.string(),
            proto_path_normalized.string()
        };
        
        std::cout << "[DEBUG] Command: ";
        for (const auto& arg : command) {
            std::cout << "\"" << arg << "\" ";
        }
        std::cout << std::endl;
        
        std::string stdout_str, stderr_str;
        if (!run_process(command, config.proto_src_dir, stdout_str, stderr_str)) {
            std::cerr << "[ERROR] Halting generation for \"" << proto_file << "\" due to previous error." << std::endl;
            fs::remove_all(local_temp_dir);
            return false;
        }

        auto [c_file, h_file] = get_output_filenames(proto_file);
        std::vector<std::string> generated_files = {c_file, h_file};
        bool files_updated = false;

        for (const auto& filename : generated_files) {
            fs::path temp_file_path = local_temp_dir / relative_dir_path / filename;
            fs::path dest_file_path = dest_subdir / filename;

            if (!fs::exists(temp_file_path)) {
                std::cout << "[WARNING] Expected generated file not found: " << temp_file_path << std::endl;
                continue;
            }

            bool should_update = true;
            if (fs::exists(dest_file_path)) {
                if (compare_files(temp_file_path, dest_file_path)) {
                    std::cout << "[INFO] No changes detected for '" << dest_file_path << "'. Skipping update." << std::endl;
                    should_update = false;
                } else {
                    std::cout << "[INFO] Changes detected in '" << dest_file_path << "'. Updating." << std::endl;
                }
            } else {
                std::cout << "[INFO] Destination file '" << dest_file_path << "' does not exist. Creating." << std::endl;
            }

            if (should_update) {
                fs::rename(temp_file_path, dest_file_path);
                files_updated = true;
            }
        }
        
        if (!files_updated) {
            std::cout << "[INFO] All generated files for " << proto_file.filename() << " are up-to-date." << std::endl;
        } else {
            std::cout << "[INFO] One or more files for " << proto_file.filename() << " were updated." << std::endl;
        }
        success = true;

    } catch (...) {
        if (fs::exists(local_temp_dir)) { fs::remove_all(local_temp_dir); }
        throw;
    }

    if (fs::exists(local_temp_dir)) { fs::remove_all(local_temp_dir); }
    return success;
}

void parse_json_config_file(const fs::path& config_path, Config& config) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open config file: " + config_path.string());
    }

    try {
        json data = json::parse(file);
        fs::path base_path = config_path.parent_path();
        
        if (data.contains("proto_src_dir")) {
            config.proto_src_dir = fs::absolute(base_path / data["proto_src_dir"].get<std::string>());
        }
        if (data.contains("output_dir")) {
            config.output_dir = fs::absolute(base_path / data["output_dir"].get<std::string>());
        }
        if (data.contains("nanopb_path")) {
            config.nanopb_path = fs::absolute(base_path / data["nanopb_path"].get<std::string>());
        }
        if (data.contains("python_executable")) {
            config.python_executable = data["python_executable"].get<std::string>();
        }
    } catch (json::parse_error& e) {
        throw std::runtime_error("JSON parse error in " + config_path.string() + ": " + e.what());
    }
}

std::pair<std::string, std::string> get_output_filenames(const fs::path& proto_file) {
    fs::path base = proto_file.stem();
    return {base.string() + ".pb.c", base.string() + ".pb.h"};
}

bool compare_files(const fs::path& path1, const fs::path& path2) {
    std::ifstream f1(path1, std::ifstream::binary | std::ifstream::ate);
    std::ifstream f2(path2, std::ifstream::binary | std::ifstream::ate);

    if (f1.fail() || f2.fail()) return false;
    if (f1.tellg() != f2.tellg()) return false;

    f1.seekg(0, std::ifstream::beg);
    f2.seekg(0, std::ifstream::beg);

    return std::equal(std::istreambuf_iterator<char>(f1.rdbuf()), std::istreambuf_iterator<char>(), std::istreambuf_iterator<char>(f2.rdbuf()));
}

#ifdef _WIN32
bool run_process(const std::vector<std::string>& command, const fs::path& working_dir, std::string& out_stdout, std::string& /*out_stderr*/) {
    // Build the command line string with proper quoting
    std::string cmd_line;
    for (size_t i = 0; i < command.size(); ++i) {
        const auto& s = command[i];
        bool needs_quoting = s.find_first_of(" \t\n\v\"") != std::string::npos;
        
        cmd_line += needs_quoting ? ("\"" + s + "\"") : s;
        if (i < command.size() - 1) cmd_line += " ";
    }

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE h_stdout_read = NULL, h_stdout_write = NULL;
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT.
    if (!CreatePipe(&h_stdout_read, &h_stdout_write, &sa, 0)) {
        std::cerr << "[ERROR] CreatePipe failed." << std::endl;
        return false;
    }
    if (!SetHandleInformation(h_stdout_read, HANDLE_FLAG_INHERIT, 0)) {
         std::cerr << "[ERROR] SetHandleInformation failed." << std::endl;
        return false;
    }
    
    si.hStdError = h_stdout_write;
    si.hStdOutput = h_stdout_write;
    si.dwFlags |= STARTF_USESTDHANDLES;

    if (!CreateProcessA(NULL, &cmd_line[0], NULL, NULL, TRUE, 0, NULL, working_dir.string().c_str(), &si, &pi)) {
        DWORD error_code = GetLastError();
        std::cerr << "[ERROR] CreateProcess failed. Error code: " << error_code << std::endl;
        
        // Provide more specific error messages
        switch (error_code) {
            case ERROR_FILE_NOT_FOUND:
                std::cerr << "[ERROR] The system cannot find the specified executable. Check if Python is installed and in PATH." << std::endl;
                break;
            case ERROR_PATH_NOT_FOUND:
                std::cerr << "[ERROR] The system cannot find the specified path. Check working directory: " << working_dir.string() << std::endl;
                break;
            case ERROR_ACCESS_DENIED:
                std::cerr << "[ERROR] Access denied. Check file permissions." << std::endl;
                break;
            default:
                std::cerr << "[ERROR] CreateProcess failed with system error code " << error_code << std::endl;
                break;
        }
        std::cerr << "[DEBUG] Command line: " << cmd_line << std::endl;
        std::cerr << "[DEBUG] Working directory: " << working_dir.string() << std::endl;
        
        CloseHandle(h_stdout_read);
        CloseHandle(h_stdout_write);
        return false;
    }
    
    CloseHandle(h_stdout_write); // Close the write end of the pipe in the parent process.

    // Read output from the child process.
    CHAR buffer[256];
    DWORD bytes_read;
    while (ReadFile(h_stdout_read, buffer, sizeof(buffer) - 1, &bytes_read, NULL) && bytes_read != 0) {
        buffer[bytes_read] = '\0';
        out_stdout += buffer;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(h_stdout_read);

    if (exit_code != 0) {
        std::cerr << "[ERROR] Process exited with code " << exit_code << std::endl;
        std::cerr << "--- Process Output ---" << std::endl << out_stdout << std::endl << "----------------------" << std::endl;
        return false;
    }
    
    return true;
}
#else
bool run_process(const std::vector<std::string>& command, const fs::path& working_dir, std::string& out_stdout, std::string& /*out_stderr*/) {
    std::vector<char*> argv;
    for (const auto& arg : command) { argv.push_back(const_cast<char*>(arg.c_str())); }
    argv.push_back(nullptr);

    pid_t pid = fork();
    if (pid == -1) { perror("fork"); return false; }

    if (pid == 0) { // Child process
        if (chdir(working_dir.c_str()) != 0) { perror("chdir"); exit(EXIT_FAILURE); }
        execvp(argv[0], argv.data());
        perror("execvp"); exit(EXIT_FAILURE);
    }

    int status;
    if (waitpid(pid, &status, 0) == -1) { perror("waitpid"); return false; }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 0) { std::cerr << "[ERROR] Process exited with code " << exit_code << std::endl; return false; }
    } else {
        std::cerr << "[ERROR] Process did not exit normally." << std::endl; return false;
    }
    return true;
}
#endif

