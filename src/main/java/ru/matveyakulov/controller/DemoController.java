package ru.matveyakulov.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.matveyakulov.client.DemoClient;

@RequiredArgsConstructor
@RestController
@RequestMapping("/demo")
public class DemoController {

    private final DemoClient demoClient;

    @GetMapping
    public void get() {
        demoClient.post();
    }

    @PostMapping
    public void post() {

    }
}
