int v1 = 12;
int v2 = 13;

void setup() {
  pinMode(v1, OUTPUT);
  pinMode(v2, OUTPUT);
}

void loop() {
  digitalWrite(v1, HIGH);
  digitalWrite(v2, LOW);
  delay(1000);                       
  digitalWrite(v2, HIGH);    
  digitalWrite(v1, LOW);  
  delay(1000);                       
}
