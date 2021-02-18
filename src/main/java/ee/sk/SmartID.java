package ee.sk;

import com.fasterxml.jackson.databind.ObjectMapper;
import ee.sk.smartid.*;
import ee.sk.smartid.rest.dao.SemanticsIdentifier;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import javax.xml.bind.DatatypeConverter;

import static java.util.stream.Collectors.joining;

@WebServlet("sign")
@MultipartConfig(fileSizeThreshold = 1024 * 1024,
        maxFileSize = 1024 * 1024 * 5,
        maxRequestSize = 1024 * 1024 * 5 * 5)
public class SmartID extends HttpServlet {
    static private final String RPURL = "https://sid.demo.sk.ee/smart-id-rp/v2/";
    static private final String RPUUID = "00000000-0000-0000-0000-000000000000";
    static private final String RPNAME = "DEMO";
    static private final String RPLEVEL = "QUALIFIED";
    static private final String API_SERVER = "https://eidas-demo.eparaksts.lv/trustedx-authserver/oauth/lvrtc-eipsign-as/token";
    static private final String SIGNAPI_SERVER = "https://signapi-prep.eparaksts.lv/";
    static private final String CLIENT_ID = "";
    static private final String CLIENT_SECRET = "";
    static private final String AUTHCERT = "";
    static private final Map<String,String> TOKEN_PARAMS = new HashMap<String, String>() {{
        put("grant_type", "client_credentials");
        put("scope", "urn:safelayer:eidas:oauth:token:introspect");
    }};
    static private final ObjectMapper objectMapper = new ObjectMapper();

    static public void main(String[] args) throws IOException, CertificateEncodingException {
        Files.write(Paths.get("test.edoc"), sign(args[0], "test.txt", "123".getBytes()));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        request.getRequestDispatcher("/index.html").include(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        try {
            Part part = request.getPart("file");
            byte[] data = new byte[(int) part.getSize()];
            part.getInputStream().read(data);
            sign(request.getParameter("ik"), part.getSubmittedFileName(), data);
        } catch (CertificateEncodingException e) {
            throw new ServletException("Failed to sign", e);
        }
    }

    static byte[] sign(String id, String fileName, byte[] data) throws IOException, CertificateEncodingException {
        String url = API_SERVER + "?" + TOKEN_PARAMS.entrySet().stream().map(Object::toString).collect(joining("&"));
        Token token = send(url, "POST", new HashMap<String, String>() {{
            put("Authorization", "Basic " + toBase64(CLIENT_ID + ":" + CLIENT_SECRET));
        }}, Token.class, null);

        Map <String, String> headers = new HashMap<String, String>() {{
            put("Authorization", token.token_type + " " + token.access_token);
        }};

        Session session = send(SIGNAPI_SERVER + "api-session/v1.0/start", "GET", headers, Session.class, null);
        File file = sendFile(SIGNAPI_SERVER + "api-storage/v1.0/" + session.data.sessionId + "/upload", headers, fileName, data);

        SmartIdClient client = new SmartIdClient();
        client.setRelyingPartyUUID(RPUUID);
        client.setRelyingPartyName(RPNAME);
        client.setHostUrl(RPURL);

        SmartIdCertificate certificateResponse = client
            .getCertificate()
            .withSemanticsIdentifier(new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.EE, id))
            .withCertificateLevel(RPLEVEL)
            .fetch();

        DigestRequest digestRequest = new DigestRequest(new SessionID[] {new SessionID(session.data.sessionId)},
                toBase64(certificateResponse.getCertificate().getEncoded()), false, false);
        Digest digest = sendJson(SIGNAPI_SERVER + "api-sign/v1.0/calculateDigest", headers, Digest.class, digestRequest);

        SignableHash hashToSign = new SignableHash();
        hashToSign.setHashType(HashType.SHA256);
        hashToSign.setHashInBase64(digest.data.sessionDigests[0].digest);
        System.out.println("Verification code: " + hashToSign.calculateVerificationCode());

        SmartIdSignature smartIdSignature = client
                .createSignature()
                .withDocumentNumber(certificateResponse.getDocumentNumber())
                .withSignableHash(hashToSign)
                .withCertificateLevel(RPLEVEL)
                .sign();

        FinalizeSignatureRequest finalizeSignatureRequest = new FinalizeSignatureRequest(new FinalizeSignatureRequest.SignatureValue[]{
                new FinalizeSignatureRequest.SignatureValue(session.data.sessionId, smartIdSignature.getValueInBase64())}, AUTHCERT);
        FinalizeSignature finalizeSignature = sendJson(SIGNAPI_SERVER + "api-sign/v1.0/finalizeSigning", headers, FinalizeSignature.class, finalizeSignatureRequest);

        FileList list = send(SIGNAPI_SERVER + "api-storage/v1.0/" + session.data.sessionId + "/list", "GET", headers, FileList.class, null);
        byte[] container = send(SIGNAPI_SERVER + "api-storage/v1.0/" + session.data.sessionId + "/" + list.data[0].id, "GET", headers, byte[].class, null);

        send(SIGNAPI_SERVER + "api-session/v1.0/" + session.data.sessionId + "/close", "GET", headers, null, null);
        return container;
    }

    interface Body {
        void send(HttpURLConnection conn) throws IOException;
    }

    private static <T> T send(String url, String method, Map<String, String> headers, Class<T> valueType, Body body) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod(method);
        conn.setRequestProperty("Cache-Control", "no-cache");
        if (headers != null) {
            headers.forEach(conn::setRequestProperty);
        }
        if (body != null) {
            body.send(conn);
        }
        if (valueType == null) {
            return null;
        }
        if (valueType.isArray()) {
            try (InputStream is = conn.getInputStream()) {
                ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                int nRead;
                byte[] data = new byte[16384];
                while ((nRead = is.read(data, 0, data.length)) != -1) {
                    buffer.write(data, 0, nRead);
                }

                return (T) buffer.toByteArray();
            }
        }
        T value = objectMapper.readValue(conn.getInputStream(), valueType);
        System.out.println(value);
        return value;
    }

    private static <T> T sendJson(String url, Map<String, String> headers, Class<T> valueType, Object request) throws IOException {
        return send(url, "POST", headers, valueType, conn -> {
            if (request != null) {
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setDoOutput(true);
                System.out.println(objectMapper.writeValueAsString(request));
                objectMapper.writeValue(conn.getOutputStream(), request);
            }
        });
    }

    private static File sendFile(String url, Map<String, String> headers, String filename, byte[] data) throws IOException {
        return send(url, "PUT", headers, File.class, conn -> {
            final String boundary = "------------------------" + Long.toHexString(System.currentTimeMillis());
            conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + boundary);
            conn.setDoOutput(true);
            try (OutputStream out = conn.getOutputStream();
                 PrintWriter body = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), true)) {
                String CRLF = "\r\n";
                body.append("--").append(boundary).append(CRLF);
                body.append("Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"").append(CRLF);
                body.append("Content-Type: application/octet-stream").append(CRLF);
                body.append("Content-Transfer-Encoding: binary").append(CRLF);
                body.append(CRLF);
                body.flush();
                out.write(data);
                out.flush();
                body.append(CRLF);
                body.append("--").append(boundary).append("--").append(CRLF);
            }
        });
    }

    static private String toBase64(String data) {
        return toBase64(data.getBytes());
    }
    static private String toBase64(byte[] data) {
        return DatatypeConverter.printBase64Binary(data);
    }

    @Data
    private static class Token {
        String scope;
        String access_token;
        String token_type;
        int expires_in;
    }

    @Data
    private static class Error {
        String code;
        String message;
        Error[] details;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    private static class SessionID {
        String sessionId;
    }

    @Data
    private static class Session {
        SessionID data;
        Error error;
    }

    @Data
    private static class File {
        @Data
        private static class FileData {
            String id;
            String name;
            int size;
            String type;
        }
        FileData data;
        Error error;
    }

    @Data
    @AllArgsConstructor
    private static class DigestRequest {
        SessionID[] sessions;
        String certificate;
        boolean signAsPdf;
        boolean createNewEdoc;
    }

    @Data
    private static class Digest {
        @Data
        private static class DigestData {
            @Data
            private static class SessionDigest
            {
                String sessionId;
                String digest;
            }
            SessionDigest[] sessionDigests;
            String digests_summary;
            String algorithm;
        }
        DigestData data;
        Error error;
    }

    @Data
    @AllArgsConstructor
    private static class FinalizeSignatureRequest
    {
        @Data
        @AllArgsConstructor
        private static class SignatureValue {
            String sessionId;
            String signatureValue;
        }
        SignatureValue[] sessionSignatureValues;
        String authCertificate;
    }

    @Data
    private static class FinalizeSignature
    {
        @Data
        private static class Result
        {
            SessionID[] results;
        }
        Result data;
        Error error;
    }

    @Data
    private static class FileList
    {
        @Data
        private static class FileInfo {
            @Data
            private static class Metadata {
                String id;
                String name;
                Integer size;
                String type;
            }
            String id;
            String name;
            Integer size;
            String type;
            Metadata[] includedDocuments;
        }
        FileInfo[] data;
    }
}
