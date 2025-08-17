project('anticheat_user', 'cpp')
# option('tracy_enable', type : 'boolean', value: true, description : 'Enable profiling')
# add_project_link_arguments('-static-libgcc', language: 'cpp')
# inc = include_directories('TSS.CPP/include')

run_command('protoc', '--proto_path=../', '--cpp_out=./generated/', '../fingerprint.proto', check: true)
source_files = [
    'dllmain.cpp', 'fingerprint.cpp',
    'crypto.cpp',
    'generated/fingerprint.pb.cc',
    # 'TSS.CPP/Src/Tpm2.cpp',
]

tss_proj = subproject('TSS.CPP')
tss_dep = tss_proj.get_variable('tss_dep')
protobuf = dependency('protobuf')
libsodium = dependency('libsodium')
tracy = dependency('tracy', static: true)

# add_project_arguments('-DTRACY_ENABLE', language: 'c')

shared_library('anticheat_user', source_files, dependencies: [tss_dep, protobuf, libsodium, tracy], link_args: ['bcrypt.lib', 'wbemuuid.lib', 'Ws2_32.lib', 'iphlpapi.lib'])

