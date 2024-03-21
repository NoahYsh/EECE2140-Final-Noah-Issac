# -*- coding: utf-8 -*-
"""
Created on Thu Mar 21 10:55:02 2024

@author: round
"""
from pypdf import PdfReader 

def read_file():
    file_to_open = input("Enter File Name: ")
    #checks to see if input is a .txt file
    if(file_to_open[-1] == 't'):
        clean_lines = []
        opened_file = open(file_to_open,'r')
        lines = opened_file.readlines()
        
        #gets ride of \n and appends to clean_lines list
        for i in range(len(lines)):
            clean_lines.append(lines[i].strip())
        opened_file.close()
        return clean_lines
    #checks to see if input is a .pdf file
    elif(file_to_open[-1] == 'f'):
        pages = []
        opened_pdf = PdfReader(file_to_open)
        
        for i in range(len(opened_pdf.pages)):
            page = (opened_pdf.pages[i].extract_text())
            #gets ride of \n that appear between between words. The \n is a result of the .extract_text() function proccessing each word on a new line
            pages.append(page.replace("\n"," "))
            
        return pages
    

def write_file(data): 
    #data to be added should be formatted in a list. linebreaks will be inserted between indices
    #works best with .txt files, will work with .pdf files but formatting will be poor
    file_to_open = input("Enter .txt file you want to write to: ")
    opened_file = open(file_to_open, 'w')
    
    for i in range(len(data)):
        opened_file.write(data[i])
        opened_file.write("\n")
    
    opened_file.close()



print(read_file())

write_file(read_file())