#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <string>
#include <functional>

#define EDR_WEB_PORT 9630
#define EDR_WEB_HOST "127.0.0.1"

void StartWebServer();
void StopWebServer();
void BroadcastNotification(const std::string& type, const std::string& title, const std::string& message);

#endif
