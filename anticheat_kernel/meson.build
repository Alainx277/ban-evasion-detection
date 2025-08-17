# adapted from https://github.com/mesonbuild/meson/discussions/11291#discussioncomment-7061464
project('mydriver', 'c', 'cpp', meson_version: '>= 0.64.0',
    default_options:['c_std=c99', 'cpp_std=vc++20', 'buildtype=release', 'b_vscrt=static_from_buildtype',
        'bindir=.', 'libdir=.', 'localedir=locale', 'b_ndebug=if-release', 'c_winlibs=', 'warning_level=2',
        'optimization=0'])

if host_machine.system() != 'windows'
    error('This project only builds on windows')
endif
if host_machine.cpu_family() == 'aarch64'
    wdkplat = 'arm64'
elif host_machine.cpu_family() == 'x86_64'
    wdkplat = 'x64'
else
    error('Unsupported platform in meson.build!')
endif

install_dir = meson.project_build_root() / 'driver'

wdkver = get_variable('wdkver', '10.0.17134.0')
wdkroot = get_variable('wdkroot', 'C:\\Program Files (x86)\\Windows Kits\\10')
message('Using WDK ' + wdkver + ' from ' + wdkroot)
wdkinc = [
    include_directories(wdkroot / 'Include' / wdkver / 'shared'),
    include_directories(wdkroot / 'Include' / wdkver / 'km'),
    include_directories(wdkroot / 'Include' / wdkver / 'km/crt'),
]
wdklib = wdkroot / 'Lib' / wdkver / 'km' / wdkplat

plat_cflags = []
if host_machine.cpu_family() == 'aarch64'
    plat_cflags += [
        '/D_WIN64',
        '/D_ARM64_',
        '/DARM64',
    ]
elif host_machine.cpu_family() == 'x86_64'
    plat_cflags += [
        '/D_WIN64',
        '/D_AMD64_',
        '/DAMD64',
        '/Gz',  # default __stdcall
    ]
else
    error('Unsupported CPU in meson.build!')
endif

# These compile and link flags come from old DDK's TARGETTYPE=DRIVER
drv_cflags = plat_cflags + [
    '/D_NO_CRT_STDIO_INLINE', # unresolved external symbol __stdio_common_vswprintf on newer DDKs
    '/DWIN32',
    '/DWINVER=0x602',
    '/D_WIN32_WINNT=0x602', # TODO make it match below?
    '/DNTDDI_VERSION=NTDDI_WIN10',
    '/DWIN32_LEAN_AND_MEAN=1',

    '/WX',  # error on warning
    '/GS',  # security checks
    '/GF',  # read-only string pooling
    '/GR-', # no RTTI
    '/Gy',  # separate functions for linker
    '/Zp8', # pack structures
    '/Zl',  # omit default library name in obj
    '/kernel',      # kernel mode binary
    '/FIwarning.h', # disable warnings in WDK headers
]

drv_ldflags = [
    '/MERGE:_PAGE=PAGE',
    '/MERGE:_TEXT=.text',
    '/SECTION:INIT,d',
    '/OPT:REF',
    '/OPT:ICF',
    '/IGNORE:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4218,4235',
    '/INCREMENTAL:NO',
    '/release', # TODO debug support
    '/NODEFAULTLIB',
    '/WX',
    '/debug',
    '/debugtype:cv,fixup,pdata',
    '/version:10.0',
    '/osversion:10.0',
    '/functionpadmin:6',
    '/pdbcompress',
    '/STACK:0x40000,0x1000',
    '/driver',
    '/base:0x1C0000000',
    '/LIBPATH:' + wdklib,
    'libcntpr.lib',
    # Original linked with hotpatch.obj, this is no longer provided for Windows 10 lib dirs, so presumably unnecessary    	
    '/entry:GsDriverEntry',
    'ntoskrnl.lib',
    'hal.lib',
    'wmilib.lib',
]

if host_machine.cpu_family() == 'aarch64'
    drv_ldflags += ['BufferOverflowfastfailK.lib']
else
    drv_ldflags += ['BufferOverflowK.lib']
endif

############################################

drv_src = [
  'mydriver.c',
]

drv_inc = [
    wdkinc,
    include_directories('.'),
]

windows = import('windows')
drv_res = windows.compile_resources('mydriver.rc', include_directories: [ drv_inc ])

mydriver = executable('mydriver',
            name_suffix: 'sys',
                sources: [drv_src, drv_res],
    include_directories: drv_inc,
                 c_args: drv_cflags,
              link_with: [],
              link_args: drv_ldflags,
          win_subsystem: 'native,6.01',
            install_dir: install_dir,
                install: true)
