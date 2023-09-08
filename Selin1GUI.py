import PySimpleGUI as sg
import pefile
import time
import codecs as cd
sg.theme('Reddit')

def analysis(execfile):
    dos_layout = [
        [sg.Text('----DOSHeader----')],
        [sg.Text('{0}: {1}'.format('e_magic',hex(execfile.DOS_HEADER.e_magic)))],
        [sg.Text('{0}: {1}'.format('e_lfanew', hex(execfile.DOS_HEADER.e_lfanew)))]
    ]
    fileHeader_layout = [
        [sg.Text('----FileHeader----')],
        [sg.Text('{0}: {1}'.format('Machine',hex(execfile.FILE_HEADER.Machine)))],
        [sg.Text('{0}: {1}'.format('NumberOfSections',execfile.FILE_HEADER.NumberOfSections))],
        [sg.Text('TimeDateStamp: {}'.format(time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.localtime(execfile.FILE_HEADER.TimeDateStamp))))],
        [sg.Text('{0}: {1}'.format('NumberOfSymbols',hex(execfile.FILE_HEADER.NumberOfSymbols)))],
        [sg.Text('{0}: {1}'.format('SizeOfOptionalHeader', execfile.FILE_HEADER.SizeOfOptionalHeader))],
        [sg.Text('{0}: {1}'.format('Characteristics', hex(execfile.FILE_HEADER.Characteristics)))]
    ]
    optional_layout = [
        [sg.Text('----OptionalHeader----')],
        [sg.Text('{0}: {1}'.format('Magic',hex(execfile.OPTIONAL_HEADER.Magic)))],
        [sg.Text('{0}: {1}'.format('Major',execfile.OPTIONAL_HEADER.MajorLinkerVersion))],
        [sg.Text('{0}: {1}'.format('Minor',execfile.OPTIONAL_HEADER.MinorLinkerVersion))],
        [sg.Text('{0}: {1}'.format('SizeOfCode',execfile.OPTIONAL_HEADER.SizeOfCode))],
        [sg.Text('{0}: {1}'.format('SizeOfInitializedData',execfile.OPTIONAL_HEADER.SizeOfInitializedData))],
        [sg.Text('{0}: {1}'.format('SizeOfUninitializedData',execfile.OPTIONAL_HEADER.SizeOfUninitializedData))],
        [sg.Text('{0}: {1}'.format('AddressOfEntryPoint',hex(execfile.OPTIONAL_HEADER.AddressOfEntryPoint)))],
        [sg.Text('{0}: {1}'.format('ImageBase',hex(execfile.OPTIONAL_HEADER.ImageBase)))],
        [sg.Text('{0}: {1}'.format('BaseOfCode',hex(execfile.OPTIONAL_HEADER.BaseOfCode)))],
        [sg.Text('{0}: {1}'.format('BaseOfData',hex(execfile.OPTIONAL_HEADER.BaseOfData)))],
    ]
    section_layout = [
        [sg.Text('{0} | {1} | {2} | {3}'.format(sec.name,hex(sec.VirtualAddress),hex(sec.Misc_VirtualSize),sec.SizeOfRawData))] for sec in execfile.sections
    ]
    execfile.parse_data_directories()
    imported_layout = [
        [sg.Text('{0} {1}'.format(entry.dll,imp.name))] for entry in execfile.DIRECTORY_ENTRY_IMPORT for imp in entry.imports
    ]
    layout = [
        [
            sg.Text('----DOSHeader----',justification='c'),
            sg.VSeparator(),
            sg.Text('    ----FileHeader----',justification='c'),
            sg.VSeparator(),
            sg.Text('----OptionalHeader---- ',justification='c'),
            sg.VSeparator(),
            sg.Text('----SECTION HEADERS----',justification='c'),
            sg.VSeparator(),
            sg.Text('----IMPORTED----',justification='c')
        ],
        [
            sg.Column(dos_layout,element_justification='c'),
            sg.VSeparator(),
            sg.Column(fileHeader_layout,element_justification='c'),
            sg.VSeparator(),
            sg.Column(optional_layout,element_justification='c'),
            sg.VSeparator(),
            sg.Column(section_layout,element_justification='c'),
            sg.VSeparator(),
            sg.Column(imported_layout,scrollable=True,vertical_scroll_only=True,element_justification='c')
        ]
    ]

    window = sg.Window('ЗИВПО пр. №2', layout, size=(1440,720),element_justification='center')
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
    window.close()

def win_init():
    start_menu = [
        [sg.Image(filename='kbsp.png')],
        [sg.Text('Защита информации от вредоносного программного обеспечения. Практика 2.')],
        [sg.Text('Выполнил студент группы БББО-11-20 Эберзин М.А.')],
        [sg.Button('Анализировать исполняемый файл', key='-1-', size=(30, 4))]
    ]
    layout = [
        [
            sg.Column(start_menu,element_justification='c')
        ]
    ]
    window = sg.Window('ЗИВПО пр. №2', layout, size=(580, 415),element_justification='center')
    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        if event == '-1-':
            try:
                execfile = pefile.PE(sg.popup_get_file('Выберите исполняемый файл для анализа', title='Выбрать файл',
                                                       file_types=(('ALL Files', '*.exe'),)), fast_load=True)
                window.Hide()
                analysis(execfile)
                window.UnHide()
            except(FileNotFoundError,BaseException):
                sg.popup('Что-то пошло не так', title='Error')
                window.UnHide()

    window.close()


if __name__ == '__main__':
    win_init()