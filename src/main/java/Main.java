import controller.HomeController;
import controller.IPController;
import io.javalin.Javalin;


public class Main {

    public static void main(String[] args) {

        Javalin app = Javalin.create();

        app.get("ipscanner/", HomeController.welcome);
        app.get("ipscanner/domains", IPController.getAllDomains);

        app.start(8080);
    }
}