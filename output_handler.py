import os

class OutputHandler:
    """ Handles any file outputs and formatting
    """
    
    def __init__(self, output_filename, file_type):
        self.output_filename = output_filename
        self.file_type = file_type
        self.createFile()
        
    def createFile(self):
        full_filename = self.output_filename + self.file_type
        if os.path.exists(full_filename):
            os.remove(full_filename)
        self.file = open(full_filename, "a")
        self.file.write("[\n")
        
    def appendJSON(self, data):
        line = "{"
        for key in data:
            line += '"' + key + '": "' + data[key] + '", '
        if len(data) > 0:
            line = line[:-2]
        line += "}\n"
        self.file.write(line)
    
    def closeFile(self):
        self.file.write("]")
        self.file.close()
    