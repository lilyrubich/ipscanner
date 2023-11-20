package controller;

import io.javalin.http.Handler;
import model.IPScanner;
import org.apache.http.entity.ContentType;

import java.io.File;
import java.io.InputStream;
import java.util.Objects;


public class IPController {

    public static Handler getAllDomains = ctx -> {
        String ip = Objects.requireNonNull(ctx.queryParam("ip"));
        int threadCount = Integer.parseInt(Objects.requireNonNull(ctx.queryParam("thread_count")));
        IPScanner ipScanner = new IPScanner();

        String fileName = "domains";
        String home = System.getProperty("user.home");
        String saveFilePath = home + File.separator + "Downloads" + File.separator + fileName + ".txt";
        String domains = ipScanner.getDomainNamesAsFile(ip, threadCount, saveFilePath);


        ctx.contentType(ContentType.TEXT_HTML.toString());
        InputStream in = HomeController.class.getResourceAsStream("/public/home.html");
        ctx.attribute("domains", domains);
        ctx.result(in);


        if (!domains.isEmpty()) {
            ctx.html("File with results downloaded to the path " + saveFilePath);
            System.out.println("Found domain names:");
            System.out.println(domains);
        } else {
            ctx.html("Domains not found");
            System.out.println("Domains not found");
        }
    };
}
