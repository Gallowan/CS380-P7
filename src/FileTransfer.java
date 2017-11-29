/**
 * CS 380.01 - Computer Networks
 * Professor: NDavarpanah
 *
 * Project 7
 * FileTransfer
 *
 * Justin Galloway
 */

import java.io.*;
import java.net.*;
import java.util.Scanner;

import java.util.zip.CRC32;
import java.util.zip.Checksum;
import java.security.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class FileTransfer {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("server") && args[1].equals("private.bin") && args[2].equals("38005")) {
            serverMode(args[1], Integer.parseInt(args[2]));
        } else if (args[0].equals("client") && args[1].equals("public.bin") && args[2].equals("localhost") && args[3].equals("38005")) {
            clientMode(args[1], args[2], Integer.parseInt(args[3]));
        } else if (args[0].equals("makekeys")) {
            generateKeys();
        } else {
            System.out.println("Wrong input!");
        }
    }

    // Server Mode
    public static void serverMode(String bin, int port) throws Exception {
        try {
            ServerSocket serverSoc = new ServerSocket(port);
            Socket socket = serverSoc.accept();
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            FileOutputStream fos = null;
            Object obj;
            StartMessage sm;
            Chunk chunk;
            SecretKeySpec sks = null;
            int chunkNum = 0;

            while (true) {
                obj = ois.readObject();
                if (obj.getClass().equals(StartMessage.class)) {
                    sm = (StartMessage) obj;
                    chunkNum = (int) sm.getSize() / sm.getChunkSize();

                    String newFileCreation = sm.getFile();
                    int dot = newFileCreation.indexOf('.');
                    String file_name = newFileCreation.substring(0, dot) + "2" + newFileCreation.substring(dot);
                    fos = new FileOutputStream(file_name);

                    Cipher cipher = Cipher.getInstance("RSA");
                    ObjectInputStream privateOis = new ObjectInputStream(new FileInputStream(bin));
                    obj = privateOis.readObject();

                    PrivateKey prK = (PrivateKey) obj;
                    cipher.init(Cipher.DECRYPT_MODE, prK);
                    byte[] enKey = cipher.doFinal(sm.getEncryptedKey());
                    sks = new SecretKeySpec(enKey, "AES");
                    oos.writeObject(new AckMessage(0));
                } else if (obj.getClass().equals(Chunk.class)) {
                    AckMessage ack;
                    int ackCount = 0;
                    while (true) {
                        if (ackCount != 0) {
                            obj = ois.readObject();
                        }
                        chunk = (Chunk) obj;

                        if(ackCount == chunk.getSeq()){
                            Cipher cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.DECRYPT_MODE, sks);
                            byte[] data = cipher.doFinal(chunk.getData());
                            Checksum checksum = new CRC32();
                            checksum.update(data, 0, data.length);
                            int checksumVal = (int)checksum.getValue();

                            if(checksumVal == chunk.getCrc()) {
                                if(ackCount < chunkNum){
                                    fos.write(data);
                                    fos.flush();
                                } else if(ackCount == chunkNum){
                                    socket.close();
                                    break;
                                }
                                ackCount++;
                                oos.writeObject(new AckMessage(ackCount));
                                System.out.println("Chunk received [" + ackCount + "/" + chunkNum + "].");
                            } else {
                                oos.writeObject(new AckMessage(ackCount));
                            }
                        } else {
                            oos.writeObject(new AckMessage(ackCount));
                        }
                    }
                    if (ackCount == chunkNum) {
                        break;
                    }
                } else if (obj.getClass().equals(DisconnectMessage.class)) {
                    socket.close();
                    break;
                }
            }
            System.out.println("Transfer complete.");
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }

    // Client Mode
    public static void clientMode(String bin, String host, int port) throws Exception {
        try {
            boolean flag = true;
            while(flag){
                Socket soc = new Socket(host, port);
                String addr = soc.getInetAddress().getHostAddress();
                System.out.printf("%s Connected%n", addr);

                ObjectOutputStream oos = new ObjectOutputStream(soc.getOutputStream());
                ObjectInputStream ois = new ObjectInputStream(soc.getInputStream());

                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                SecretKey sk = kg.generateKey();

                byte[] secKey = sk.getEncoded();
                ObjectInputStream publicOis = new ObjectInputStream(new FileInputStream(bin));
                Object obj = publicOis.readObject();
                PublicKey puK = (PublicKey) obj;
                Cipher c = Cipher.getInstance("RSA");
                c.init(Cipher.ENCRYPT_MODE, puK);
                byte[] enKey = c.doFinal(secKey);

                System.out.print("Enter path for file: ");
                Scanner k = new Scanner(System.in);
                String path = k.nextLine();
                System.out.print("Enter chunk size [1024]: ");
                int chunkSize = k.nextInt();

                File copyFile = new File(path);
                long fileSize = copyFile.length();
                StartMessage sm = new StartMessage(path, enKey, chunkSize);
                oos.writeObject(sm);
                obj = ois.readObject();

                AckMessage ack = (AckMessage) obj;
                if (ack.getSeq() != -1) {
                    FileInputStream dupFile = new FileInputStream(path);
                    int ackCount = ((int) sm.getSize()) / chunkSize;
                    Cipher aes = Cipher.getInstance("AES");
                    aes.init(Cipher.ENCRYPT_MODE, sk);
                    System.out.println("Sending: " + path + ". File size: " + sm.getSize() + ".\n");
                    int count = 0;
                    byte[] data;
                    Checksum checksum;
                    while(ack.getSeq() < ackCount){
                        if (count >= 1) {
                            obj = ois.readObject();
                            ack = (AckMessage) obj;
                        }

                        if (ackCount != ack.getSeq()) {
                            data = new byte[chunkSize];
                        } else {
                            int remainder = ((int) sm.getSize()) - (chunkSize * (ack.getSeq()));
                            data = new byte[remainder];
                        }

                        int num = dupFile.read(data);
                        checksum = new CRC32();
                        checksum.update(data, 0, data.length);
                        int checksumVal = (int) checksum.getValue();
                        byte[] chunkData = aes.doFinal(data);
                        Chunk chunkArray = new Chunk(ack.getSeq(), chunkData, checksumVal);
                        oos.writeObject(chunkArray);
                        System.out.println("Chunks completed [" + ack.getSeq() + "/" + ackCount + "].");
                        count++;
                        flag = false;
                    }
                }
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Keygen; given in project instructions.
    public static void generateKeys() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(4096);
            KeyPair keyPair = gen.genKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("public.bin")))) {
                oos.writeObject(publicKey);
            }
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("private.bin")))) {
                oos.writeObject(privateKey);
            }
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace(System.err);
        }
    }
}