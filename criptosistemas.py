#-*- coding: utf-8 -*-
import string
import random
import sys
import string 
import time
import base64
import codecs
import math
from operator import itemgetter

def menu():
    if len(sys.argv) <  5:
        print ("------------------------------------------------------Ayuda-------------------------------------------------------")
        print ("La forma correcta de ejecutar este archivo es : python criptosistemas.py [archivo_entrada] [-c/-d] [algoritmo] [Base64 (opcional)] [archivo_salida]")
        print ("-c: para cifrar")
        print ("-d: para decifrar")
        print ("-b64: para codificacion Base64")
        print ("ALGORITMOS: -t  ---> Transposicion simple")
        print ("            -ti ---> Transposicion inversa")
        print ("            -td ---> Transposicion doble")
        print ("            -ts ---> Transposicion por series")
        print ("            -v  ---> Vernam ")
        print ("            -a  ---> ADFGVX ")
        print ("            -c  ---> COLOSSUS")
        print ("EJEMPLO DE CIFRADO: python criptosistemas.py quijote.txt -c -t cifrado_simple")
        print ("EJEMPLO DE DESCIFRADO: python criptosistemas.py cifrado_simple.cif -d -t claro_simple")
        print ("EJEMPLO DE CIFRADO CON CODIFICACION BASE 64: python criptosistemas.py quijote.txt -c -t -b64 cifrado_simple")
        print ("EJEMPLO DE DESCIFRADO CON CODIFICACION BASE 64:: python criptosistemas.py cifrado_simple.cif -d -t -b64 claro_simple")

    else:
        if sys.argv[3] == "-t":
            if sys.argv[2] == "-c":
                
                print("Cifrando...")
                texto = leer_archivo(sys.argv[1])
                texto = limpiarTexto(texto, sys.argv[1])
                
                if(len(sys.argv)>5): ##codificacion con base 64

                    if(sys.argv[4]=="-b64"):
                        texto=encode_base64(texto)
                        inicio = time.clock()
                        a,b = reparte_grupos2(texto)
                        fin=time.clock()-inicio
                        print("Proceso terminado en",fin,"segundos")
                        archivo = sys.argv[5]+".cif"
                        escribe_archivo(archivo,a+b)
                    else:
                        print("error...")

                else:
                    inicio = time.clock()
                    a,b = reparte_grupos2(texto)
                    fin=time.clock()-inicio
                    print("Proceso terminado en",fin,"segundos")
                    archivo = sys.argv[4]+".cif"
                    escribe_archivo(archivo,a+b)

            elif sys.argv[2] =="-d":

                print("Descifrando...")
                inicio = time.clock()    
                texto=leer_archivo(sys.argv[1])
                
                if(len(sys.argv)>5): ##codificacion con base 64

                    if(sys.argv[4]=="-b64"):
                        t_claro = decifrar_transpocisionS(texto)
                        fin=time.clock()-inicio
                        t_claro=decode_base64Simple(t_claro)
                        t_claro=textoOriginal(t_claro, sys.argv[1])
                        print("Proceso terminado en",fin,"segundos")
                        archivo = sys.argv[5]+".dec"
                        escribe_archivo(archivo,t_claro)
                    else:
                        print("error...")

                else:
                    t_claro = decifrar_transpocisionS(texto)
                    fin=time.clock()-inicio
                    t_claro=textoOriginal(t_claro, sys.argv[1])
                    print("Proceso terminado en",fin,"segundos")
                    archivo = sys.argv[4]+".dec"
                    escribe_archivo(archivo,t_claro)

        elif sys.argv[3] == "-ti":
            if sys.argv[2] == "-c":

                print("Cifrando...")
                inicio = time.clock()
                texto = leer_archivo(sys.argv[1])
                texto = limpiarTexto(texto, sys.argv[1])

                if(len(sys.argv)>5):
                    if(sys.argv[4]=="-b64"):
                        texto=encode_base64(texto)
                        cifrado_simple = invertir(texto)
                        fin=time.clock()-inicio
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".cif",cifrado_simple)
                    else:
                        print("error...")

                else:

                    cifrado_simple = invertir(texto)
                    fin=time.clock()-inicio
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".cif",cifrado_simple)

            elif sys.argv[2] =="-d": 

                print("Descifrando...")
                inicio = time.clock()
                texto = leer_archivo(sys.argv[1])

                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):
                        descifrado_simple = invertir(texto)
                        descifrado_simple=decode_base64Simple(descifrado_simple)
                        descifrado_simple=textoOriginal(descifrado_simple, sys.argv[1])
                        fin=time.clock()-inicio
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".dec",descifrado_simple)
                    else:
                        print("error...")

                else:
                    descifrado_simple = invertir(texto)
                    descifrado_simple=textoOriginal(descifrado_simple, sys.argv[1])
                    fin=time.clock()-inicio
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".dec",descifrado_simple)

        elif sys.argv[3] == "-td":
            if sys.argv[2] == "-c":

                print("Cifrando...")
                inicio = time.clock()
                texto = leer_archivo(sys.argv[1])
                texto = limpiarTexto(texto, sys.argv[1])

                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):
                        texto=encode_base64(texto)
                        a,b = reparte_grupos(texto)
                        cifrado_doble_uno=a+b
                        c,d = reparte_grupos2(cifrado_doble_uno)
                        fin=time.clock()-inicio
                        #print (c+d)
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".cif",c+d)

                    else:
                        print("error...")

                else:
                    a,b = reparte_grupos2(texto)
                    cifrado_doble_uno=a+b
                    c,d = reparte_grupos2(cifrado_doble_uno)
                    fin=time.clock()-inicio
                    #print (c+d)
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".cif",c+d)

            elif sys.argv[2] =="-d": 

                print("Descifrando...")
                inicio = time.clock()    
                texto=leer_archivo(sys.argv[1])
                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):

                        cript = decifrar_transpocisionS(texto)
                        t_claro = decifrar_transpocisionS(cript)
                        t_claro=decode_base64Simple(t_claro)
                        t_claro=textoOriginal(t_claro, sys.argv[1])
                        fin=time.clock()-inicio
                        #print(t_claro)
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".dec",t_claro)
                    else:
                        print("error...")

                else:
                    cript = decifrar_transpocisionS(texto)
                    t_claro = decifrar_transpocisionS(cript)
                    t_claro=textoOriginal(t_claro, sys.argv[1])
                    fin=time.clock()-inicio
                    #print(t_claro)
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".dec",t_claro)

        elif sys.argv[3] == "-ts":
            if sys.argv[2] == "-c":

                print("Cifrando...")
                
                texto = leer_archivo(sys.argv[1])
                texto = limpiarTexto(texto, sys.argv[1])
                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):
                        texto=encode_base64(texto)
                        inicio = time.clock()
                        cript=cifrar_series(texto)
                        fin=time.clock()-inicio
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".cif",cript)
                    else:
                        print("error...")
                else:

                    inicio = time.clock()
                    cript=cifrar_series(texto)
                    fin=time.clock()-inicio
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".cif",cript)

            elif sys.argv[2] =="-d":    

                print("Descifrando...")
                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):
                        inicio = time.clock()    
                        cripto=leer_archivo(sys.argv[1])
                        texto_claro=descifrar_series(cripto)
                        texto_claro=decode_base64(texto_claro)
                        texto_claro=textoOriginal(texto_claro, sys.argv[1])
                        fin=time.clock()-inicio
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".dec",texto_claro)
                    else:
                        print("error...")
                else:

                    inicio = time.clock()    
                    cripto=leer_archivo(sys.argv[1])
                    texto_claro=descifrar_series(cripto)
                    texto_claro=textoOriginal(texto_claro, sys.argv[1])
                    fin=time.clock()-inicio
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".dec",texto_claro)

        elif sys.argv[3] == "-v":
            if sys.argv[2] == "-c":

                print("Cifrando...")
                inicio = time.clock()    
                texto_claro=leer_archivo(sys.argv[1])
                #texto_claro = limpiarTexto(texto_claro, sys.argv[1])
                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):
                        texto_claro=encode_base64(texto_claro)
                        txt_bin = text_to_bits(texto_claro)
                        clave = key_generator(len(texto_claro))
                        key_binario= text_to_bits(clave)
                        cifrado_bin=or_exclusivo(txt_bin,key_binario)
                        cifrado_vernam =text_from_bits(cifrado_bin)
                        fin=time.clock()-inicio
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".cif",cifrado_bin)
                        escribe_archivo('kVernam.txt',key_binario)
                    else:
                        print("error")
                else:
                    txt_bin = text_to_bits(texto_claro)
                    clave = key_generator(len(texto_claro))
                    key_binario= text_to_bits(clave)
                    cifrado_bin=or_exclusivo(txt_bin,key_binario)
                    cifrado_vernam =text_from_bits(cifrado_bin)
                    fin=time.clock()-inicio
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".cif",cifrado_bin)
                    escribe_archivo('kVernam.txt',key_binario)

            elif sys.argv[2] =="-d":    
                
                print("Descifrando...")
                inicio = time.clock()    
                texto=leer_archivo(sys.argv[1])
                if(len(sys.argv)>5):
                    
                    if(sys.argv[4]=="-b64"):
                        clave = leer_archivo("kVernam.txt")
                        #key_binario= text_to_bits(clave)
                        descifrado_bin=or_exclusivo(texto,clave)
                        descifrado_vernam =text_from_bits(descifrado_bin)
                        descifrado_vernam=decode_base64(descifrado_vernam)
                        descifrado_vernam=textoOriginal(descifrado_vernam, sys.argv[1])
                        fin=time.clock()-inicio
                        #print (descifrado_vernam)
                        print("Proceso terminado en",fin,"segundos")
                        escribe_archivo(sys.argv[5]+".dec",descifrado_vernam)
                   
                    else:
                        print("error...")

                else:
                #txt_bin = text_to_bits(texto)
                    clave = leer_archivo("kVernam.txt")
                    #key_binario= text_to_bits(clave)
                    descifrado_bin=or_exclusivo(texto,clave)
                    descifrado_vernam =text_from_bits(descifrado_bin)
                    descifrado_vernam=textoOriginal(descifrado_vernam, sys.argv[1])
                    fin=time.clock()-inicio
                    #print (descifrado_vernam)
                    print("Proceso terminado en",fin,"segundos")
                    escribe_archivo(sys.argv[4]+".dec",descifrado_vernam)
                   
            
        elif sys.argv[3] == "-a":

            if sys.argv[2] == "-c":
                print("Cifrando...")
                  
                clave=leer_archivo("claveADFGVX.txt")
                texto_claro=leer_archivo(sys.argv[1])
                texto_claro = limpiarTexto(texto_claro, sys.argv[1])
                inicio = time.clock()  

                cripto=cifrar_ADFGVX(texto_claro, clave)
                fin=time.clock()-inicio
                print("Proceso terminado en",fin,"segundos")
                escribe_archivo(sys.argv[4]+".cif",cripto)

            elif sys.argv[2] =="-d":
                print("Descifrando...")
                clave=leer_archivo("claveADFGVX.txt")
                cripto=leer_archivo(sys.argv[1])
                inicio = time.clock()  

                texto_claro = descifrar_ADFGVX(cripto, clave)
                texto_claro=textoOriginal(texto_claro, sys.argv[1])
                fin=time.clock()-inicio
                print("Proceso terminado en",fin,"segundos")
                escribe_archivo(sys.argv[4]+".dec",texto_claro)

        ###aqui va el colossus
        elif sys.argv[3] == "-c":

            if sys.argv[2] == "-c":
                print("aqui cifra")
            elif sys.argv[2] =="-d":
                print("aqui descrifra")


letra_clave = ['A', 'D', 'F', 'G', 'V', 'X']
alfabeto_clave = [ ['A', 'B', 'C', 'D', 'E', 'F'], ['G', 'H', 'I', 'J', 'K', 'L'], ['M', 'N', 'O', 'P', 'Q', 'R'], ['S', 'T', 'U', 'V', 'W', 'X'], ['Y', 'Z', '0', '1', '2', '3'], ['4', '5', '6', '7', '8', '9'] ]

#Funcion para leer el contenido de un archivo 
def leer_archivo(archivo):
    texto = open(archivo, 'r', encoding = "latin-1")
    texto = texto.read()
    return texto


def escribe_archivo(nombre, contenido):
    f = open(nombre, 'w', encoding = "latin-1")
    f.write(contenido)
    f.close()

def encode_base64(texto):
    b64 = base64.b64encode(bytes(texto,"latin-1"))
    return b64

def decode_base64(texto):
    txt = base64.b64decode(texto).decode("latin-1")
    return txt

def decode_base64Simple(texto):
    txt = base64.b64decode(bytes (texto + '=' * (-len(texto) % 4),"latin-1")).decode("latin-1")
    #txt = base64.decodestring(bytes(texto + '=' * (-len(texto) % 4)))
    return txt


def limpiarTexto(texto, archivo):

    if(archivo in "quijote.txt"):

        texto = texto.replace('Ñ', '0')
        texto = texto.replace(']', '1')
        texto = texto.replace('Ü', '2')
        texto = texto.replace('«', '6')
        texto = texto.replace('Ï', '4')
        texto = texto.replace('À', '5')
        texto = texto.replace('Ù', '7')
    else:
        texto = texto.replace('_', '0')
        texto = texto.replace(']', '1')
        texto = texto.replace('[', '2')
        texto = texto.replace('%', '3')
        texto = texto.replace('\n', '4')
    return texto

def textoOriginal(texto, archivo):

    if(archivo[:6] in "quijote.txt"):
        print('entro')
        texto = texto.replace('0', 'Ñ')
        texto = texto.replace('1', ']')
        texto = texto.replace('2', 'Ü')
        texto = texto.replace('6', '«')
        texto = texto.replace('4', 'Ï')
        texto = texto.replace('5', 'À')
        texto = texto.replace('7', 'Ù')
    else:
        texto = texto.replace('0', '_')
        texto = texto.replace('1', ']')
        texto = texto.replace('2', '[')
        texto = texto.replace('3', '%')
        texto = texto.replace('4', '\n')
    
    return texto

def reparte_grupos(texto):
    indice = 1
    grupo1=""
    grupo2=""
    for caracter in texto:
        if indice%2 != 0:
            grupo1+=chr(caracter)
        else:
            grupo2+=chr(caracter)
        indice += 1
    return grupo1,grupo2

def reparte_grupos2(texto):
    indice = 1
    grupo1=""
    grupo2=""
    for caracter in texto:
        if indice%2 != 0:
            grupo1+=caracter
        else:
            grupo2+=caracter
        indice += 1
    return grupo1,grupo2
    
def tamano_grupo_simple(texto):
    tam = len(texto)//2
    if len (texto)%2!=0:
        tam = (len(texto)//2)+1
    return tam
        
def decifrar_transpocisionS(texto):
    
    tamano = tamano_grupo_simple(texto)
    texto_claro=""
    for i  in range(tamano):
        if i==(tamano-1):
            texto_claro += texto[i]
        else:
            texto_claro += texto[i] + texto[i+(tamano)]
    return texto_claro

#reemplazar por la ""ñ"
def reemplazar(cadena,busca, reemplazo):
    
	    cadena1 = cadena.replace(busca,reemplazo)
	    return cadena1

	#esta funcion invierte la cadena de texto    
def invertir(texto):
        return texto[::-1]

def archivo():
    return leer_archivo("quijote.txt")
#Cifrado de VERNAM

#funcion que genera una llave aleatoria del cuerpo = chars y con tamaño= tamano (mismo tamaño del texto claro) 
def key_generator(tamano,chars='ABCDEFGHIJKLMNÑOPQRSTUVWXYZ'):
    size =tamano 
    return ''.join(random.choice(chars) for _ in range(size))
#funcion para obtener el binario apartir de texto
def text_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int.from_bytes(text.encode(encoding, errors), 'big'))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))
#funcion para obtener el  texto apartir de binario
def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

#funcion que recibe el texto ckro en binario y la clave en binario y retorna el resultado de aplicar el XOR bit por bit
def or_exclusivo(texto_bin, clave_bin):
    cifrado=""
    for i in range(len(texto_bin)):
        
        if texto_bin[i]== clave_bin[i]:
            cifrado += str(0)
        else :
            cifrado+=str(1)
    return cifrado

##funcion de transposición por series
def cifrar_series(texto):

    texto_encode=texto
    n_texto = len(texto_encode)
    
    array_par=list(map(int, leer_archivo('func_series/func_par.txt').split(',')))
    array_impar=list(map(int, leer_archivo('func_series/func_impar.txt').split(',')))
    array_primo = list(map(int, leer_archivo('func_series/func_primo.txt').split(',')))

    #array_par = map(int, array_par) #python version menor a 3

    n_par=len(array_par)
    n_impar=len(array_impar)
    n_primo=len(array_primo)

    txt_f1=[]
    txt_f2=[]
    txt_f3=[]

    for i in range(0,n_texto):

        if(i<n_par):
            pos_f1 = array_par[i]-1
            if(pos_f1 < n_texto):
                txt_f1.append(texto_encode[pos_f1])

        if(i<n_impar):
            pos_f2 = array_impar[i]-1
            if(pos_f2 < n_texto):
                txt_f2.append(texto_encode[pos_f2])

        if(i<n_primo):
            pos_f3 = array_primo[i]-1
            if(pos_f3 < n_texto):
                txt_f3.append(texto_encode[pos_f3])

    criptograma="".join(txt_f3)+"".join(txt_f1)+"".join(txt_f2)
    return criptograma

def descifrar_series(cript):

    cripto=cript
    array_par=list(map(int, leer_archivo('func_series/func_par.txt').split(',')))
    array_impar=list(map(int, leer_archivo('func_series/func_impar.txt').split(',')))
    array_primo = list(map(int, leer_archivo('func_series/func_primo.txt').split(',')))

    n_par=len(array_par)
    n_impar=len(array_impar)
    n_primo=len(array_primo)

    primo=[]
    par=[]
    impar=[]

    n_cripto=len(cripto)

    for i in range(n_cripto):

        if(i<n_primo):
            pos_f1=array_primo[i]-1
            if(pos_f1 < n_cripto):
                primo.append((pos_f1, cripto[i]))

    pos_par=0
    n_primo=len(primo)
    for i in range(n_primo ,n_cripto):

        if(i<n_par):
            pos_f2=array_par[pos_par]-1;
            if(pos_f2 < n_cripto):
                par.append((pos_f2, cripto[i]))
            pos_par+=1

    pos_impar=0
    n_par=len(par)
    for i in range((n_primo+n_par), n_cripto):

        if(i<n_impar):
            pos_f3=array_impar[pos_impar]-1
            if(pos_f3 < n_cripto):
                impar.append((pos_f3, cripto[i]))
            pos_impar+=1


    array_texto=primo+par+impar
    array_texto.sort(key=itemgetter(0))
    txt=""
    for i in range(0,len(array_texto)):
        txt+=array_texto[i][1]   

    return txt

def cifrar_ADFGVX(texto_claro, txt_clave):
    
    texto_clave=""
    n_alfabeto=len(alfabeto_clave)
    for i in texto_claro:
        x=0
        y=0
        for j in range(0, n_alfabeto):
            try:
                x = alfabeto_clave[j].index(i)
                y=j
                texto_clave += letra_clave[y] + letra_clave[x]
            except ValueError:
                pass

    #SEPARO EN BLOQUES DE TAMANO DE LA CLAVE
    pos_texto=0
    tam_texto=len(texto_clave)
    msg_bloque = list()
    while pos_texto < tam_texto:

        txt_list = list()
        for i in range(0,len(txt_clave)):
            try:
                txt_list.append(texto_clave[pos_texto])
            except IndexError:
                break
            pos_texto = pos_texto + 1
        msg_bloque.append(txt_list)
    
    #ORDENO LOS BLOQUES DE FORMA ASCENDENTE A LA CLAVE
    lista_claves = list()
    msg_bloque_d = dict()
    for i in range(0,len(txt_clave)):
        txt_list = list()
        for j in range(0,len(msg_bloque)):
            try:
                txt_list.append(msg_bloque[j][i])
            except IndexError:
                pass
        lista_claves.append(txt_clave[i])
        msg_bloque_d[txt_clave[i]] = txt_list
    lista_claves.sort()
    clave_orden= "".join(lista_claves)

    #print(msg_block_d)
    #print(sorted_string)

    msg_bloque_t = list() #bloques transpuestos
    for i in range(0,len(msg_bloque)):
        txt_list = list()
        for j in range(0,len(clave_orden)):
            try:
                txt_list.append(msg_bloque_d[clave_orden[j]][i])
            except IndexError:
                txt_list.append(" ") ##completa con espacios
                pass
        msg_bloque_t.append(txt_list)

    criptograma = ""
    for i in range(0,len(clave_orden)):
        for j in range(0,len(msg_bloque_t)):
            if msg_bloque_t[j][i] != " ":
                try:
                    criptograma += msg_bloque_t[j][i]
                except IndexError:
                    pass
        criptograma = criptograma + " "
    return criptograma
                                                    

####final cifrado

def descifrar_ADFGVX(criptograma, txt_clave):
    
    cripto_list =criptograma.split(" ")
    
    trans_list = list()
    txt_list = list()
    for i in range(0, len(txt_clave)):
        trans_list.append(txt_clave[i])
        txt_list.append(txt_clave[i])
    txt_list.sort()

    max_len = 0
    for i in range(0, len(cripto_list)):
        if len(cripto_list[i]) > max_len: max_len = len(cripto_list[i])

    msg_bloque = dict()
    for i in range(0, len(txt_clave)):
        lista = list()
        for j in range(0, max_len):
            try:
                lista.append(cripto_list[i][j])
            except IndexError:
                lista.append(" ")
        msg_bloque[txt_list[i]] = lista

    sorted_string = "".join(txt_list)

    index_txt = ""
    for i in range(0, max_len):
        for j in range(0, len(txt_clave)):
            index_txt += msg_bloque[txt_clave[j]][i]

    texto_claro = ""
    for i in range(0, len(index_txt), 2):
        indexloc_a = 0
        indexloc_b = 0
        try:
            index_x = letra_clave.index(index_txt[i])
            index_y = letra_clave.index(index_txt[i+1])
            texto_claro += str(alfabeto_clave[index_x][index_y])
        except ValueError:
            pass

    return texto_claro

menu()
#leer_archivo("quijote.txt")    

