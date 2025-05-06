package ru.matveyakulov.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/demo")
public class DemoController {

    @GetMapping
    public void get() {
        // бизнес логика
    }

    @PostMapping
    public void post() {

    }
}
