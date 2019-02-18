//I=Inlet;O=Outlet
int valves[2][2] = {{12,13},{14,15}};

void setup()
{
  for(int i=0 ; i<2 ; i++)
    for(int j=0 ; j<2 ; j++)
      valves[i][j] = 0;
}

void inflate(int n)
{
 digitalWrite(valves[n+1][0],HIGH);
 digitalWrite(valves[n+1][1],LOW); 
}
void exhaust(int n)
{
 digitalWrite(valves[n+1][0],LOW);
 digitalWrite(valves[n+1][1],HIGH); 
}
void hold(int n)
{
 digitalWrite(valves[n+1][0],LOW);
 digitalWrite(valves[n+1][1],LOW) ;
}
void hold_all()
{
 hold(1);
 hold(2); 
}

void loop() 
{
                         
}
