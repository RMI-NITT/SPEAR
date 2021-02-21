#include <SimpleKalmanFilter.h>
#include <Statistic.h>

SimpleKalmanFilter Jineshd(2, 2, 0.001), Jineshp(2, 10, 0.001);
Statistic d_stats, p_stats;

uint16_t i=0;

uint16_t d=0, Dorsi_Estimate=0;
double d_mean=0, d_stddev=0, d_threshold=0;

uint16_t p=0, Plantar_Estimate=0;
double p_mean=0, p_stddev=0, p_threshold=0;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  Serial.flush();
  d_stats.clear();
  p_stats.clear();
  delay(1000);
  Serial.flush();
}

void loop() {
  // put your main code here, to run repeatedly:
  d = analogRead(A1);
  p = analogRead(A2);

  Dorsi_Estimate = Jineshd.updateEstimate(d);
  Plantar_Estimate = Jineshp.updateEstimate(p);
  
  i++;
  if(i==10)
  {
    
    
    if(millis()<10000)
    {
      Serial.println("Calibrating...");
      d_stats.add(d);
      d_mean = d_stats.average();
      d_stddev = d_stats.pop_stdev();
      d_threshold = (d_mean+(5*d_stddev));

      
      p_stats.add(p);
      p_mean = p_stats.average();
      p_stddev = p_stats.pop_stdev();
      p_threshold = (p_mean+(2*p_stddev));      
    }
/*
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
    Serial.println(p_threshold);*/
  if(millis()>10000)
  {
    if((Dorsi_Estimate - d_threshold)>0)   
      Serial.println("Dorsiflexion");
    else if(((Dorsi_Estimate - d_threshold)<0) && ((Plantar_Estimate - p_threshold)>0))
      Serial.println("Plantarflexion");
    else if(((Dorsi_Estimate - d_threshold)<0) && ((Plantar_Estimate - p_threshold)<0))
      Serial.println("No movement");
  }   
  i=0;
  }
  delay(5);
}
