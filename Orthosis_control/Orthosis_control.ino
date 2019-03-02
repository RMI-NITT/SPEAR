//I=Inlet; O=Outlet

int valves[2][2] = {{9,10},{11,12}};

void inflate(int n)
{
 digitalWrite(valves[n-1][0],HIGH);
 digitalWrite(valves[n-1][1],LOW); 
}

void exhaust(int n)
{
 digitalWrite(valves[n-1][0],LOW);
 digitalWrite(valves[n-1][1],HIGH); 
}

void hold(int n)
{
 digitalWrite(valves[n-1][0],LOW);
 digitalWrite(valves[n-1][1],LOW) ;
}

void hold_all()
{
 hold(1);
 hold(2); 
}

void setup()
{
  hold_all();
}

void loop() 
{
  inflate(1);
  delay(5000);
  exhaust(1);
  delay(2500);
  inflate(2);
  delay(5000);
  exhaust(2);
  delay(2500);
  inflate(1);
  inflate(2);
  hold_all();
  exhaust(1);
  exhaust(2);
  delay(2500);                         
}
