package model;

import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.ConnectException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Callable;


public class SSLScannerTask implements Callable<Set<String>> {

    private int firstIP;
    private int lastIP;
    private Set<String> domains = new HashSet<>();

    public SSLScannerTask(int firstIP, int lastIP) {
        this.firstIP = firstIP;
        this.lastIP = lastIP;
    }

    @Override
    public Set<String> call() {
        try {
            if (firstIP != lastIP) {
                for (int ip = firstIP; ip <= lastIP; ip++) {
                    scanIP(ip);
                }
            } else scanIP(firstIP);
        } catch (IOException | NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException(e);
        }
        return domains;
    }

    private void scanIP(int ip) throws IOException, NoSuchAlgorithmException, KeyManagementException {

        //parse ip address from int value
        byte[] addressArray = intToBytes(ip);
        String address = addressArray[0] + "." + addressArray[1] + "." + addressArray[2] + "." + addressArray[3];

        try {

            SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(address, 443);
            socket.startHandshake();

            SSLSession session = socket.getSession();

            if (session.isValid()) {
                Certificate[] certificates = session.getPeerCertificates();

                try {
                    for (Certificate certificate : certificates) {
                        if (certificate instanceof X509Certificate) {
                            X509Certificate x509Certificate = (X509Certificate) certificate;

                            if (x509Certificate.getSubjectAlternativeNames() == null)
                                continue;

                            String[] domainNames = x509Certificate.getSubjectAlternativeNames()
                                    .stream()
                                    .filter(entry -> entry.get(0).equals(2))
                                    .map(entry -> (String) entry.get(1))
                                    .toArray(String[]::new);

                            for (String domainName : domainNames) {
                                domains.add(domainName);
                            }
                        }
                    }

                } catch (CertificateParsingException e) {
                    throw new RuntimeException(e);
                } finally {
                    socket.close();
                }
            }
        } catch (ConnectException e) {
            System.out.println(e + " : Host " + address + " doesn't answer");
        }
    }

    private byte[] intToBytes(int ip) {
        return new byte[]{
                (byte) (ip >> 24),
                (byte) (ip >> 16),
                (byte) (ip >> 8),
                (byte) ip
        };
    }
}
