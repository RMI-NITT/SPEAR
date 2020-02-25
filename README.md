# SPEAR
This project is aimed for Rehabilitation of Stroke patients suffering from foot drop - a gait abnormality caused by the paralysis of anterior portion muscles of the lower leg.
We designed a 1-DOF Soft Active Ankle-Foot Orthosis, which is actuated using Pneumatic Artificial Muscle (PAM)

The Control of Orthosis is done based on user intent, using the Electromyography (EMG) signals from the muscles involved in the action of the ankle. A dynamic threshold is set initially, and when the EMG signal crosses the threshold value, the solenoid valve which acts as a gate opens, and the PAM actuate along with the movement of leg thus helping with the rehabilitation.

* Actuator_test -> Test of actuator using solenoid valves.
* EMG_Dorsi     -> Testing of EMG sensor in Dorsiflexion movement.
* First_Integration -> Contains the final code of actuator control using EMG sensor in both dorsiflexion and plantarflexion.
* Orthosis_control.ino -> Contains the control of 2 solenoid valves for the dorsi and plantar movements with a fixed delay 
