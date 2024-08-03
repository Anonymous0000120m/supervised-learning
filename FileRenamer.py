import os  
import re  
import logging  
from logging.handlers import RotatingFileHandler  

class FileRenamer:  
    def __init__(self, source_directory, output_directory, dictionary_file, log_file='renamer.log', max_log_size=10*1024*1024):  # 10MB  
        self.source_directory = source_directory  
        self.output_directory = output_directory  
        self.logger = self.setup_logger(log_file, max_log_size)  
        self.module_dict = {}  # Словарь для хранения имен модулей  
        self.component_dict = {}  # Словарь для хранения компонентных имен  

        # Загружаем словари из файла  
        self.load_dictionaries(dictionary_file)  

        # Убедитесь, что выходная директория существует  
        os.makedirs(self.output_directory, exist_ok=True)  

    def setup_logger(self, log_file, max_log_size):  
        logger = logging.getLogger('FileRenamer')  
        logger.setLevel(logging.INFO)  

        handler = RotatingFileHandler(log_file, maxBytes=max_log_size, backupCount=5)  
        handler.setLevel(logging.INFO)  

        console_handler = logging.StreamHandler()  
        console_handler.setLevel(logging.ERROR)  

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')  
        handler.setFormatter(formatter)  
        console_handler.setFormatter(formatter)  

        logger.addHandler(handler)  
        logger.addHandler(console_handler)  

        return logger  

    def load_dictionaries(self, dictionary_file):  
        """ Загрузка словарей модулей и компонент из текстового файла. """  
        try:  
            with open(dictionary_file, 'r', encoding='utf-8') as file:  
                for line in file:  
                    module_name, component_name = line.strip().split(',')  
                    self.module_dict[module_name] = component_name  
        except Exception as e:  
            self.logger.error(f"Failed to load dictionaries: {e}")  

    def rename_files(self):  
        for filename in os.listdir(self.source_directory):  
            if filename.endswith('.txt'):  
                file_path = os.path.join(self.source_directory, filename)  
                try:  
                    with open(file_path, 'r', encoding='utf-8') as file:  
                        new_filename, component_names = self.process_file(file, filename)  
                        if new_filename:
                            self.save_file(new_filename, component_names)  
                except Exception as e:  
                    self.logger.error(f"Failed to process '{filename}': {e}")  

    def process_file(self, file, filename):  
        module_name = None  
        component_names = []  
        for line in file:  
            matches = re.findall(r'(\w+)\.java', line)  
            if matches:  
                module_name = matches[0] if module_name is None else module_name  
                component_names.extend(matches)  

        if module_name and component_names:  
            new_filename = self.create_new_filename(module_name, component_names)  
            return new_filename, component_names  
        return None, []  

    def create_new_filename(self, module_name, component_names):  
        """ Создаем новое имя файла с использованием модуля и компонентного имен. """  
        component_name = component_names[0]  
        return f"{module_name}_{self.module_dict.get(component_name, component_name)}.txt"  

    def save_file(self, new_filename, component_names):  
        new_file_path = os.path.join(self.output_directory, new_filename)  
        try:  
            with open(new_file_path, 'w', encoding='utf-8') as new_file:  
                new_file.write(f"Modified file: {new_filename}\n")  # Мы можем изменить содержимое файла  
                new_file.write("\nComponent Names:\n")  
                new_file.write("\n".join(component_names))  
            self.logger.info(f"Saved modified file as '{new_filename}' in '{self.output_directory}'")  
        except Exception as e:  
            self.logger.error(f"Failed to save '{new_filename}': {e}")  

# Использование  
source_directory = 'path_to_your_source_directory'  
output_directory = 'path_to_your_output_directory'  
dictionary_file = 'path_to_your_dictionary_file.txt'  
renamer = FileRenamer(source_directory, output_directory, dictionary_file)  
renamer.rename_files()  
