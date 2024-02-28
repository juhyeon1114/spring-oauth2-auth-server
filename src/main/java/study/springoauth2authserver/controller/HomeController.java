package study.springoauth2authserver.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class HomeController {

    @GetMapping("/")
    public String root() {
        return "/";
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }
}
