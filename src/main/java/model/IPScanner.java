package model;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.*;

public class IPScanner {


    public Set<String> getDomainNames(String ipRangeWithMask, int numberOfThreads) throws ExecutionException, InterruptedException {

        int[] rangeOfIpAddresses = getRangeOfIpAddresses(ipRangeWithMask);
        int firstIP = rangeOfIpAddresses[0];
        int lastIP = rangeOfIpAddresses[1];

        int numberOfIp = lastIP - firstIP + 1;
        int countOfIpPerThread = numberOfIp / numberOfThreads;

        Set<String> domains = new CopyOnWriteArraySet<>();

        ExecutorService executor = Executors.newFixedThreadPool(numberOfThreads);

        for (int i = 0; i < numberOfThreads; i++) {
            int firstIpPerThread = firstIP + i * countOfIpPerThread;

            int lastIpPerThread = firstIpPerThread + countOfIpPerThread - 1;

            //distribute the rest of the addresses
            if (i == numberOfThreads - 1 && lastIpPerThread < lastIP && firstIpPerThread != lastIpPerThread)
                lastIpPerThread = lastIP;

            SSLScannerTask sslScannerTask = new SSLScannerTask(firstIpPerThread, lastIpPerThread);
            Future<Set<String>> futureTask = executor.submit(sslScannerTask);

            domains.addAll(futureTask.get());
        }
        return domains;
    }

    public String getDomainNamesAsFile(String ipRangeWithMask, int numberOfThreads, String saveFilePath) throws ExecutionException, InterruptedException, IOException {

        Set<String> domains = getDomainNames(ipRangeWithMask, numberOfThreads);

        StringBuilder stringBuilder = new StringBuilder();

        for (String setElement : domains) {
            stringBuilder.append(setElement);
            stringBuilder.append(System.lineSeparator());
        }

        String setString = stringBuilder.toString().trim();
        byte[] setBytes = setString.getBytes(StandardCharsets.UTF_8);

        if (!domains.isEmpty()) {

            Files.write(Path.of(saveFilePath), setBytes);
            System.out.println("File downloaded to the path " + saveFilePath);
        } else {
            System.out.println("No file to download. The reason can be empty file.");
        }
        return setString;
    }

    private int[] getRangeOfIpAddresses(String ipRangeWithMask) {

        String[] ipWithMask = ipRangeWithMask.split("/");

        String[] inputIpOctets = ipWithMask[0].split("\\.");
        int[] inputIp = new int[4];
        for (int i = 0; i < 4; i++) {
            inputIp[i] = Integer.parseInt(inputIpOctets[i]);
        }

        int[] mask = getMaskFromInt(Integer.parseInt(ipWithMask[1]));

        int[] firstAddress = getFirstAddress(inputIp, mask);
        int[] lastAddress = getLastAddress(firstAddress, mask);

        String firstAddressStr = firstAddress[0] + "." + firstAddress[1] + "." + firstAddress[2] + "." + firstAddress[3];
        String lastAddressStr = lastAddress[0] + "." + lastAddress[1] + "." + lastAddress[2] + "." + lastAddress[3];


        try {
            InetAddress inetFirstAddress = InetAddress.getByName(firstAddressStr);
            InetAddress inetLastAddress = InetAddress.getByName(lastAddressStr);

            return new int[]{
                    bytesToInt(inetFirstAddress.getAddress()),
                    bytesToInt(inetLastAddress.getAddress())
            };

        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private int bytesToInt(byte[] bytes) {
        int value = 0;
        for (byte b : bytes) {
            value = (value << 8) | (b & 0xFF);
        }
        return value;
    }

    private int[] getMaskFromInt(int value) {
        int shft = 0xffffffff << (32 - value);
        return new int[]{
                ((shft & 0xff000000) >> 24) & 0xff,
                ((shft & 0x00ff0000) >> 16) & 0xff,
                ((shft & 0x0000ff00) >> 8) & 0xff,
                ((shft & 0x000000ff)) & 0xff};
    }

    private int[] getFirstAddress(int[] inputIpAddress, int[] mask) {
        int[] result = new int[4];
        for (int i = 0; i < 4; i++) {
            result[i] = inputIpAddress[i] & mask[i];
        }
        return result;
    }

    private int[] getLastAddress(int[] firstIpAddress, int[] mask) {
        int[] result = new int[4];
        for (int i = 0; i < 4; i++) {
            result[i] = (~mask[i] | firstIpAddress[i]) + 256;
        }
        return result;
    }
}