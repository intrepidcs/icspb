# icspb

## Description
This repository contains protobufs leveraging nanopb intended for device communication and settings storage

## Usage
### Generating C/C++ source files
The source files for the protobufs are intended to be generated using the nanopb_generator.py Python script found in the nanopb Github repository.
This repository contains a script `proto_gen.py` that can be used to generate the output as a pre-build step for a project to keep the output in sync with the proto definitions.

### Packing
The protobuf parser must know how many bytes to process in order to correctly deserialize the message. This is how each protobuf should be packaged
1. varint encoded byte length of the following header
2. SettingsHeader message
3. Protobuf described in the SettingsHeader

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
protobuf license: https://github.com/protocolbuffers/protobuf/blob/main/LICENSE
nanopb license: https://github.com/nanopb/nanopb/blob/master/LICENSE.txt
