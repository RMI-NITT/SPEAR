int v1 = 12;
int v2 = 13;

void setup() {
  pinMode(v1, OUTPUT);
  pinMode(v2, OUTPUT);
  digitalWrite(v2, HIGH);
}

void loop() 
{
  digitalWrite(v1, HIGH);
  delay(50);
  digitalWrite(v1,LOW);                      
  delay(1000);
}
