#pragma once

class WebApp {
public:
    explicit WebApp(int port = 8080);

    int run();

private:
    int port_;
};
