package ru.matveyakulov;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication
@EnableFeignClients(basePackages = "ru.matveyakulov.client")
public class LightWeightApp {

    public static void main(String[] args) {
        SpringApplication.run(LightWeightApp.class, args);
    }
}