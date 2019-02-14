#include <SimpleKalmanFilter.h>
#include <Statistic.h>

SimpleKalmanFilter Jinesh(2, 2, 0.001);
Statistic myStats;

uint16_t val=0, Kalman_Estimate=0, i=0, j=0, k=0, op =0;
double mean=0, stddev=0, threshold=0;
void setup() {
  // put your setup code here, to run once:
  Serial.begin(9600);
  Serial.flush();
  pinMode(A0,OUTPUT);
  myStats.clear();
  delay(1000);
  Serial.flush();
}

void loop() {
  // put your main code here, to run repeatedly:
  val=analogRead(A0);

  Kalman_Estimate = Jinesh.updateEstimate(val);
  
  i++;j++;
  if(i==10)
  {
    Serial.print(val);  
    Serial.print('\t');
    Serial.print(Kalman_Estimate);
    Serial.print('\t');
    if(millis()<10000)
    {
      myStats.add(Kalman_Estimate);
      mean = myStats.average();
      stddev = myStats.pop_stdev();
      threshold = (mean+(3*stddev));
    }
    Serial.println(threshold);
    if (millis()>12000)
    {
      if(Kalman_Estimate>threshold)
      {
        //Serial.println('1');
      }
      else
      {
        //Serial.println('0');
      }
    }
/*    Serial.print('\t');
    Serial.println(op);
    if(Kalman_Estimate > 45)
        Serial.println("Tight");
    else if(Kalman_Estimate > 15)
        Serial.println("Loose");
    else
        Serial.println("Jinesh DEAD");  */
    i=0;
  }
  
  delay(5);
}
