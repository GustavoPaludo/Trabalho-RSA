package com.udesc.seguranca;

import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSAEncryption {

    private BigInteger n, d, e;
    private static final SecureRandom random = new SecureRandom();

    //O bitlen é o tamanho de N, neste caso que é de 2048 bits
    public RSAEncryption(int bitlen) {

        //Geração de dois primos grandes e edistintos
        BigInteger p = BigInteger.probablePrime(bitlen, random);
        BigInteger q = BigInteger.probablePrime(bitlen, random);
        
        //Módulo
        n = p.multiply(q);

        //Fórmula de Euler
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        
        //O número E será gerado da mesma forma que os primos anteriores, mas com um N de tamanho diferente
        int keyLength = 256;
        e = generateRandomPrime(keyLength);
        d = e.modInverse(phi);
    }

    //Método para gerar primos aleatórios usando o método probablePrime do BigInteger
    public static BigInteger generateRandomPrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, random);
    }

    //Método que faz a criptografia mensagemCriptografada = message^e mod(n)
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    //Método que faz a decriptografia mensagemDecriptografada = mensagemCriptografada^d mod(n)
    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(d, n);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        int bitlen = 2048;
        RSAEncryption rsa = new RSAEncryption(bitlen);

        while (true) {
            System.out.print("\nDigite a mensagem a ser criptografada (ou 'exit' para sair): ");
            String message = scanner.nextLine();

            if (message.equalsIgnoreCase("exit")) {
                break;
            }

            System.out.println("\nChave Pública: \n\n n = " + rsa.n + ", \n e = " + rsa.e);
            System.out.println("\nChave Privada: \n\n n = " + rsa.n + ", \n d = " + rsa.d);
    
            BigInteger encryptedMessage = sendEncryptedMessage(rsa, message);
            receiveDecryptedMessage(rsa, encryptedMessage);
        }

        scanner.close();
    }

    public static BigInteger sendEncryptedMessage(RSAEncryption rsa, String message) {
        System.out.println("\nMensagem Original: " + message);

        BigInteger messageBigInt = new BigInteger(1, message.getBytes(StandardCharsets.UTF_8));

        BigInteger encryptedMessage = rsa.encrypt(messageBigInt);
        System.out.println("\nMensagem Criptografada: " + encryptedMessage.toString(16));
        return encryptedMessage;
    }

    public static void receiveDecryptedMessage(RSAEncryption rsa, BigInteger encryptedMessage) {
        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);

        byte[] decryptedBytes = decryptedMessage.toByteArray();
        if (decryptedBytes[0] == 0) {
            byte[] temp = new byte[decryptedBytes.length - 1];
            System.arraycopy(decryptedBytes, 1, temp, 0, temp.length);
            decryptedBytes = temp;
        }

        String decryptedString = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("\nMensagem Descriptografada: " + decryptedString);
    }
}
