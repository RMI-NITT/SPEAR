//I=Inlet; O=Outlet

#include <SimpleKalmanFilter.h>
#include <Statistic.h>

SimpleKalmanFilter Jineshd(2, 2, 0.001), Jineshp(2, 10, 0.001);
Statistic d_stats, p_stats;

int valves[2][2] = {{9,10},{11,12}};

int intent = 0;

uint16_t i=0;

uint16_t d=0, Dorsi_Estimate=0;
double d_mean=0, d_stddev=0, d_threshold=0;

uint16_t p=0, Plantar_Estimate=0;
double p_mean=0, p_stddev=0, p_threshold=0;






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



void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  Serial.flush();
  d_stats.clear();
  p_stats.clear();
  delay(1000);
  Serial.flush();
  hold_all();
}
void setup()
{
}

void loop() {
  // put your main code here, to run repeatedly:
  d = analogRead(A0);
  p = analogRead(A1);

  Dorsi_Estimate = Jineshd.updateEstimate(d);
  Plantar_Estimate = Jineshp.updateEstimate(p);
  
  i++;
  if(i==10)
  {
    
    if(millis()<10000)
    {
      d_stats.add(Dorsi_Estimate);
      d_mean = d_stats.average();
      d_stddev = d_stats.pop_stdev();
      d_threshold = (d_mean+(3*d_stddev));

      
      p_stats.add(Plantar_Estimate);
      p_mean = p_stats.average();
      p_stddev = p_stats.pop_stdev();
      p_threshold = (p_mean+(6*p_stddev));      
    }
   i=0;
    
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
  
  if((Dorsi_Estimate - d_threshold)>0)   
    intent = 1;
  else if(((Dorsi_Estimate - d_threshold)<0) && ((Plantar_Estimate - p_threshold)>0))
    intent = -1;
  else if(((Dorsi_Estimate - d_threshold)<0) && ((Plantar_Estimate - p_threshold)<0))
    intent = 0;
  }

  switch(intent)
  {
    case -1:inflate(1); //Plantarflexion
            exhaust(2);
            break;
    case 0: hold_all(); //Hold Position
            break;
    case 1: inflate(2); //Dorsiflexion
            exhaust(1);
            break;
  }
  
  delay(5);
}
