package controller;

import io.javalin.http.Handler;
import org.apache.http.entity.ContentType;

import java.io.InputStream;

public class HomeController {

    public static Handler welcome = ctx -> {
        ctx.contentType(ContentType.TEXT_HTML.toString());
        InputStream in = HomeController.class.getResourceAsStream("/public/home.html");
        ctx.result(in);
    };
}
