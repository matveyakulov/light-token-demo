package ru.matveyakulov.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;

@FeignClient(name = "demo-client", url = "http://localhost:8080")
public interface DemoClient {

    @PostMapping("/demo")
    void post();
}