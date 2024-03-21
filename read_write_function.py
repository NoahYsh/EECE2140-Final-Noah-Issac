# -*- coding: utf-8 -*-
"""
Created on Thu Mar 21 10:55:02 2024

@author: round
"""
from pypdf import PdfReader 

def read_file():
    file_to_open = input("Enter File Name: ")
    
    if(file_to_open[-1] == 't'):
        clean_lines = []
        opened_file = open(file_to_open,'r')
    
        lines = opened_file.readlines()
    
        for i in range(len(lines)):
            clean_lines.append(lines[i].strip())
        
        opened_file.close()
        return clean_lines
    
    elif(file_to_open[-1] == 'f'):
        pages = []
        opened_pdf = PdfReader(file_to_open)
        
        for i in range(len(opened_pdf.pages)):
            page = (opened_pdf.pages[i].extract_text().strip())
            pages.append(page.replace("\n"," "))
            
        return pages
    
def write_file(data):
    file_to_open = input("Enter .txt file you want to write to: ")
    opened_file = open(file_to_open, 'w')
    
    for i in range(len(data)):
        opened_file.write(data[i])
        opened_file.write("\n")
    
    opened_file.close()



print(read_file())

write_file(read_file())