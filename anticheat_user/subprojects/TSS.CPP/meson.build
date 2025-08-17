project('TSS.CPP', 'cpp')


inc = include_directories('src', 'include', 'CryptoEngine/openssl/VC-WIN64A')
source_files = [
    'Src/Crypto.cpp',
    'Src/Serialize.cpp',
    'Src/Tpm2.cpp',
    'Src/TpmAuthSessions.cpp',
    'Src/TpmDevice.cpp',
    'Src/TpmHelpers.cpp',
    'Src/TpmPolicy.cpp',
    'Src/TpmStructure.cpp',
    'Src/TpmTypeExtensions.cpp',
    'Src/TpmTypes.cpp',
]

tss = shared_library('tss_cpp', source_files,
  include_directories: inc,
  cpp_args: ['/DWIN32', '/D_TPMCPPLIB', '/wd4273', '/wd4373', '/bigobj'],
  link_args: ['ws2_32.lib', 'tbs.lib', meson.current_source_dir() + '/CryptoEngine/openssl/VC-WIN64A/libcrypto.lib'],
)

inc = include_directories('include')
tss_dep = declare_dependency(include_directories : inc, link_with : tss)
