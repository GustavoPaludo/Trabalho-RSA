package com.udesc.seguranca;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Scanner;

public class RSAEncryption {

    private BigInteger n, d, e;
    private static final SecureRandom random = new SecureRandom();

    // Construtor para gerar chaves públicas e privadas
    public RSAEncryption(int bitlen) {
        int keyLength = 256;
        BigInteger p = BigInteger.probablePrime(bitlen / 2, random);
        BigInteger q = BigInteger.probablePrime(bitlen / 2, random);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = generateRandomPrime(keyLength);
        d = e.modInverse(phi);
    }

    public static BigInteger generateRandomPrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, random);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(d, n);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Digite a mensagem a ser criptografada: ");
        String message = scanner.nextLine();
        scanner.close();

        int bitlen = 2048;
        RSAEncryption rsa = new RSAEncryption(bitlen);

        System.out.println("\nChave Pública: (n = " + rsa.n + ", e = " + rsa.e + ")");
        System.out.println("\nChave Privada: (n = " + rsa.n + ", d = " + rsa.d + ")");

        BigInteger encryptedMessage = sendEncryptedMessage(rsa, message);

        receiveDecryptedMessage(rsa, encryptedMessage);
    }

    // Método para simular o sistema de origem da mensagem
    public static BigInteger sendEncryptedMessage(RSAEncryption rsa, String message) {
        System.out.println("\nMensagem Original: " + message);

        BigInteger messageBigInt = new BigInteger(message.getBytes(StandardCharsets.UTF_8));

        BigInteger encryptedMessage = rsa.encrypt(messageBigInt);
        System.out.println("\nMensagem Criptografada: " + encryptedMessage.toString(16));
        return encryptedMessage;
    }

    // Método para simular o sistema de destino da mensagem
    public static void receiveDecryptedMessage(RSAEncryption rsa, BigInteger encryptedMessage) {
        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);

        String decryptedString = new String(decryptedMessage.toByteArray(), StandardCharsets.UTF_8);
        System.out.println("\nMensagem Descriptografada: " + decryptedString);
    }
}
