[/*
 * Pin Configurations:
 * 
 * 9  - Back Inlet
 * 10 - Back Exhaust
 * 11 - Front Inlet
 * 12 - Front Exhaust
 * A0 - Dorsiflexor EMG
 * A1 - Plantarflexor EMG
 */

#include <SimpleKalmanFilter.h>
#include <Statistic.h>

#define duty_cycle 10

SimpleKalmanFilter Dorsiflexion(2, 2, 0.001), Plantarflexion(2, 10, 0.001);
Statistic d_stats, p_stats;

float duty_time = 100 / duty_cycle; // in percentage

int valves[2][2] = {{9,10},{11,12}};
int ms = 0;
int intent = 0;

int prev_time=0, on_prev=0, off_prev=0;
bool state = false;

uint16_t i=0;

//Dorsiflexion statistics initialisation
uint16_t d=0, Dorsi_Estimate=0;
double d_mean=0, d_stddev=0, d_threshold=0;

//Plantarflexion statistics initialisation
uint16_t p=0, Plantar_Estimate=0;
double p_mean=0, p_stddev=0, p_threshold=0;

void calibrate()
{
  while(1)
  {
    d = analogRead(A0);
    p = analogRead(A1);
  
    // Dorsi_Estimate = Dorsiflexion.updateEstimate(d);
    // Plantar_Estimate = Plantarflexion.updateEstimate(p);
    if(millis()<10000)
    {
      d_stats.add(d);
      p_stats.add(p);        
    }
    else
    {
      d_mean = d_stats.average();
      d_stddev = d_stats.pop_stdev();
      d_threshold = (d_mean+(3*d_stddev));
      
      p_mean = p_stats.average();
      p_stddev = p_stats.pop_stdev();
      p_threshold = (p_mean+(6*p_stddev));
      return;
    }
  }
}

void emg_update() 
{
  // put your main code here, to run repeatedly:
  
  for (int i=0; i<10; i++)
  {
    d = analogRead(A0);
    p = analogRead(A1);
      
    Dorsi_Estimate = Dorsiflexion.updateEstimate(d);
    Plantar_Estimate = Plantarflexion.updateEstimate(p);
    delay(5);
  }
  
  /*Graphing Section
  Serial.print(d);  
  Serial.print('\t');
  Serial.print(Dorsi_Estimate);
  Serial.print('\t');
  Serial.print(d_threshold);
  Serial.print('\t');
    
  Serial.print(p);  
  Serial.print('\t');
  Serial.print(Plantar_Estimate);
  Serial.print('\t');
  Serial.print(p_threshold);
  Serial.print('\t');*/
  
  if((Dorsi_Estimate - d_threshold) > 0)   
    intent = 1;
  else if(((Dorsi_Estimate - d_threshold) < 0) && ((Plantar_Estimate - p_threshold) > 0))
    intent = -1;
  else if(((Dorsi_Estimate - d_threshold) < 0) && ((Plantar_Estimate - p_threshold) < 0))
    intent = 0;
}

void pwm(int a, int b,int c,int d)
{
  int intent_state = intent;
  
  prev_time = millis();
  while(millis() - prev_time < 5000)
  {
    on_prev = millis();
    digitalWrite(a,b);
    digitalWrite(c,d);
    while(millis() - on_prev < 50)
    {
      emg_update();
      if(intent_state!=intent)
        return;
    }
    
    off_prev = millis();
    digitalWrite(a,!b);
    digitalWrite(c,!d);
    while(millis() - off_prev < (50 * duty_time))
    {
      emg_update();
      if(intent_state!=intent)
        return;
    }
  }
}

//Valve control functions

void plantar()
{
  digitalWrite(valves[0][1],LOW);     //Inflate back  - close exhaust
  digitalWrite(valves[1][0],LOW);     //Deflate front - close inlet
  pwm(valves[0][0],1,valves[0][0],1);
  digitalWrite(valves[0][0],HIGH);    //Inflate back  - open inlet (permanently after PWM)
  digitalWrite(valves[1][1],HIGH);    //Deflate front - open exhaust (permanently after PWM)  
}

void dorsi()
{
  digitalWrite(valves[1][1],LOW);     //Inflate front - close exhaust
  digitalWrite(valves[0][0],LOW);     //Deflate back -  close inlet
  pwm(valves[1][0],1,valves[0][1],1);
  digitalWrite(valves[1][0],HIGH);    //Inflate front  - open inlet (permanently after PWM)
  digitalWrite(valves[0][1],HIGH);    //Deflate back - open exhaust (permanently after PWM)  
}

/*
void inflate(int n)
{
  digitalWrite(valves[n-1][1],LOW);
  pwm(n-1,0);
  digitalWrite(valves[n-1][0],HIGH);
}

void exhaust(int n)
{
  digitalWrite(valves[n-1][0],LOW);
  pwm(n-1,1);
  digitalWrite(valves[n-1][1],HIGH); 
}

void hold(int n)
{
  digitalWrite(valves[n-1][0],LOW);
  digitalWrite(valves[n-1][1],LOW) ;
}*/

void hold_all()
{
  digitalWrite(valves[0][0],LOW);
  digitalWrite(valves[0][1],LOW) ;

  digitalWrite(valves[1][0],LOW);
  digitalWrite(valves[1][1],LOW) ;
}

void setup() 
{
  Serial.begin(9600);
  Serial.flush();
  d_stats.clear();
  p_stats.clear();
  delay(1000);
  Serial.flush();
  hold_all();
  calibrate();
}

void loop()
{
  emg_update();
  switch(intent)
  {
    //Plantarflexion
    case -1: //inflate(1); 
             //exhaust(2);
             plantar();
             break;
            
    //Hold Position       
    case  0: hold_all(); 
             break;
            
    //Dorsiflexion
    case  1: //inflate(2); 
             //exhaust(1);
             dorsi();
             break;
  }
  delay(10);
}

