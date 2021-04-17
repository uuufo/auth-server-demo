package dev.jlarsen.authserverdemo.exceptions;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletResponse;

@Controller
public class MyErrorController implements ErrorController {

        @Override
        public String getErrorPath() {
            return "/error";
        }

        @RequestMapping("/error")
        public String handleError(HttpServletResponse response) {

            // todo - log error
            switch (response.getStatus()) {
                case 404:
                    return "/error/404";
                case 500:
                    return "/error/500";
                case 400:
                    return "/error/400";
                default:
                    return "error";
        }
    }
}