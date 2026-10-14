
#include <WiFi.h>
#include <HTTPClient.h>

const char* WIFI_SSID = "MDK";
const char* WIFI_PASSWORD = "dhyankumar";

const char* PC_IP = "10.202.178.41";
const char* API_TOKEN = "hello";

const unsigned long INTERVAL_MS = 60000;

void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  Serial.print("Connecting to Wi-Fi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWi-Fi connected");
  Serial.println(WiFi.localIP());
}

bool sendSyntheticAlert() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  WiFiClient client;
  HTTPClient http;

  String url = String("http://") + PC_IP +
               ":8766/synthetic-alert";

  if (!http.begin(client, url)) {
    Serial.println("HTTP initialization failed");
    return false;
  }

  http.addHeader("X-API-Token", API_TOKEN);

  int status = http.POST("");
  String response = status > 0 ? http.getString() : "";

  Serial.printf("HTTP status: %d\n", status);
  Serial.println(response);

  http.end();
  return status == 200;
}

void setup() {
  Serial.begin(115200);
  connectWiFi();
}

void loop() {
  Serial.println("Sending synthetic Suricata test event...");
  sendSyntheticAlert();
  delay(INTERVAL_MS);
}
