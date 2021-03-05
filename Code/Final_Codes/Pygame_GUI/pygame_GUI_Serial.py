import pygame as pg
import numpy
import serial
from pygame.locals import*

win_H=720
win_W=1280

class Border():
    def __init__(self):
        #border params
        self.bc= (150,255,205)
        self.bt=10

        #Column Widths
        self.col1=30
        self.col2=30
        self.col3=40

        #width ratio
        self.wr=win_W/(self.col1+self.col2+self.col3)

        #Row Heights
        self.row_head=150
        self.row1=337
        self.row2=337
        self.row3=256

        self.col3_r=0.7

        #height ratio
        self.hr=win_H/(self.row_head+self.row1+self.row2+self.row3)

        #Row & col points
        self.row_head_1=(0,self.row_head*self.hr)
        self.row_head_2=(win_W,self.row_head*self.hr)

        self.col1_1=(self.col1*self.wr,self.row_head_1[1])
        self.col1_2=(self.col1*self.wr,win_H)

        self.col2_1=( (self.col1+self.col2)*self.wr, self.row_head_1[1])
        self.col2_2=( (self.col1+self.col2)*self.wr,win_H)

        self.row1_1=(0, (self.row_head+self.row1)*self.hr )
        self.row1_2=(self.col2_1[0], self.row1_1[1])

        self.row2_1=(0, (self.row_head+self.row1+self.row2)*self.hr )
        self.row2_2=(self.col2_1[0], self.row2_1[1])

        self.col3_1=(self.col2_1[0], (self.row_head+self.col3_r*(win_H-self.row_head) ) )
        self.col3_2=(win_W, (self.row_head+self.col3_r*(win_H-self.row_head) ) )

    def draw(self):
        #Draw outer border
        pg.draw.polygon(win, self.bc, [(0,0),(win_W,0),(win_W,win_H),(0,win_H)],self.bt)

        #Draw cols
        pg.draw.line(win, self.bc, self.col1_1,self.col1_2,self.bt)
        pg.draw.line(win, self.bc, self.col2_1,self.col2_2,self.bt)

        #Draw rows
        pg.draw.line(win, self.bc, self.row_head_1, self.row_head_2, self.bt)
        pg.draw.line(win, self.bc, self.row1_1, self.row1_2, self.bt)
        pg.draw.line(win, self.bc, self.row2_1, self.row2_2, self.bt)
        pg.draw.line(win, self.bc, self.col3_1, self.col3_2, self.bt)


class Bar_Graph:
    def __init__(self,window):
        self.win=window
    def rect(self,_x,_y,_b,_h,_color, _thickness=0):
        _points= [ ( _x-_b/2,_y),(_x+_b/2,_y), (_x+_b/2, _y+_h), (_x-_b/2, _y+_h) ]
        pg.draw.polygon( self.win, _color, _points,_thickness )

    def draw(self,x,y,bar_count,b=31,h=8,barlet_max=10,barlet_h=10, border_gap=5,bor_color=(255,0,0),bar_color=(255,165,0)):
        y-=barlet_max*barlet_h
        #Draw Borders
        self.rect(x,y-border_gap,b+2*border_gap,h+2*border_gap+barlet_h*(barlet_max-1),bor_color, _thickness=2)
        #Draw Barlets
        for i in range(0,bar_count):
            self.rect(x,y+barlet_h*(barlet_max-i-1),b,h,bar_color)


class Text:
    def __init__(self,window):
        pg.font.init()
        self.screen=window
        
    def text_objects(self,text,font,__color):
        txtsurf = font.render(text,True,__color)
        return txtsurf, txtsurf.get_rect()

    def write(self,_text,x,y,_size=20,_color=(0,0,0)):
        font = pg.font.Font('freesansbold.ttf',_size)
        txtsf, txtre = self.text_objects(_text,font,_color)
        txtre.center = (x,y)
        self.screen.blit(txtsf,txtre)


class Leg:
    def __init__(self,window):
        self.win=window
    def draw(self,footangle=30,knee=(320,200),kneeangle=10,thighlength=120,shinlength=200,footlength=65,toeheelangle=30):
        footstart=(knee[0] - ( shinlength*numpy.sin(kneeangle * 3.14/180) ) ,knee[1] + ( shinlength*numpy.cos(kneeangle * 3.14/180) ) )
        heel=( footstart[0] + (footlength*numpy.sin(toeheelangle *3.14/180)*numpy.sin( (footangle-kneeangle) *3.14/180)) , footstart[1] + (footlength*numpy.sin(toeheelangle *3.14/180)*numpy.cos( (footangle-kneeangle) *3.14/180)) )
        toe= (heel[0] - footlength*numpy.cos(toeheelangle *3.14/180)*numpy.cos( (footangle-kneeangle) *3.14/180) , heel[1] + footlength*numpy.cos(toeheelangle *3.14/180)*numpy.sin( (footangle-kneeangle) *3.14/180) )

        pg.draw.line(self.win, (0,0,255), knee, (knee[0]+thighlength ,knee[1]), 10)
        pg.draw.line(self.win, (0,0,255), knee, footstart, 10)
        pg.draw.polygon(self.win, (255,255,255), [ footstart, heel, toe ], 10)

word_limit=100
def readValues():

    dorsi_t=0
    dorsi_v=0
    plantar_t=0
    plantar_v=0
    
    while True:
        if ard.inWaiting()!=0:
            break
    word=ard.readline().decode()

    i=1
    while True:
        if (i>word_limit):
            break
        elif( (word[i]=='\t') ):
            i+=1
            break
        if(i==1):
            dorsi_t=word[i]
        else:
            dorsi_t+=word[i]
        i+=1
    last_val=i

    while True:
        if (i>word_limit):
            break
        elif( (word[i]=='\t') ):
            i+=2
            break
        if (i==last_val):
            dorsi_v=word[i]
        else:
            dorsi_v+=word[i]
        i+=1
    last_val=i

    while True:
        if (i>word_limit):
            break
        elif( (word[i]=='\t') ):
            i+=1
            break
        if (i==last_val):
            plantar_t=word[i]
        else:
            plantar_t+=word[i]
        i+=1
    last_val=i

    while True:
        if (i>word_limit):
            break
        elif( word[i]=='\t' ):
            i+=1
            break
        if(i==last_val):
            plantar_v=word[i]
        else:
            plantar_v+=word[i]
        i+=1
    
    Dorsi_t=float(dorsi_t)
    Dorsi_v=float(dorsi_v)
    Plantar_t=float(plantar_t)
    Plantar_v=float(plantar_v)

    return (Dorsi_t,Dorsi_v,Plantar_t,Plantar_v)
        

#creating a pygame window
win = pg.display.set_mode((win_W,win_H))
running = True

#Objects Initialisations
borders = Border()
bar=Bar_Graph(win)
text=Text(win)
leg=Leg(win)

#Loading Images
dorsi_img = pg.image.load("dorsi.jpeg").convert()
dorsi_img = pg.transform.scale(dorsi_img, (160, 170))

plantar_img = pg.image.load("plantar.jpeg").convert()
plantar_img = pg.transform.scale(plantar_img, (160, 170))

#Display till Connection and Callibration
win.fill((0,0,0))
text.write('Connecting to SPEAR. . .',win_W/2 ,win_H/2,60,(0,255,0))
pg.display.update()

ard=serial.Serial('com19',9600)
while True:
        if ard.inWaiting()!=0:
            break

#To avoid python shell crash after closing a pygame window
while running:
    for event in pg.event.get():
        if(event.type == QUIT):
            running = False

    dorsi_t,dorsi_v,plantar_t,plantar_v=readValues()

    dorsi_state = dorsi_v>dorsi_t
    plantar_state = plantar_v>plantar_t

    # movement detection
    if dorsi_state:
        footangle=0     #dorsi
        movement_string='Dorsiflexion'
    elif not(dorsi_state) and plantar_state:
        footangle=60    #plantar
        movement_string='Plantarflexion'
    elif not(dorsi_state) and not(plantar_state):
        footangle=15    #idle
        movement_string='Idle'

    if dorsi_state:
        dorsi_string='Active'
    else:
        dorsi_string='Idle'

    if plantar_state:
        plantar_string='Active'
    else:
        plantar_string='Idle'

    dorsi_scale=(dorsi_v*30)/dorsi_t
    if dorsi_scale>100:
        dorsi_scale=100

    plantar_scale=(plantar_v*30)/plantar_t
    if plantar_scale>100:
        plantar_scale=100

    #Clear Screen
    win.fill((0,0,0))

    #Borders
    borders.draw()

    #Bar Graph - Dorsi
    bar1_x=(0+borders.col1_1[0])/2;
    bar1_y=(borders.row1_1[1] + 0.6*(borders.row2_1[1]-borders.row1_1[1]) )
    bar.draw(bar1_x, bar1_y,int(dorsi_scale/10) )

    #Bar graph - Plantar
    bar2_x=(borders.col1_1[0]+borders.col2_1[0])/2;
    bar2_y=bar1_y
    bar.draw(bar2_x, bar2_y,int(plantar_scale/10) )

    #Images
    win.blit(dorsi_img, ( borders.col1_1[0]/2 -80 ,(borders.row_head_1[1]+borders.row1_1[1])/2 -85 +18) )
    win.blit(plantar_img, ( (borders.col1_1[0]+borders.col2_1[0])/2 -80 ,(borders.row_head_1[1]+borders.row1_1[1])/2 -85 +18) )

    #Leg
    leg.draw(footangle=footangle,knee=( (borders.col2_1[0]+win_W)/2 , borders.row_head_1[1] + 145) )
    
    #Text Entries
    text.write('EMG State',win_W/2,borders.row_head_1[1]/2,45,(255,255,255) )

    text.write('Dorsiflexion',borders.col1_1[0]/2,borders.row_head_1[1] + 0.175*(borders.row1_1[1]-borders.row_head),25,(255,255,0) )
    text.write('Plantarflexion',(borders.col1_1[0]+borders.col2_2[0])/2,borders.row_head_1[1] + 0.175*(borders.row1_1[1]-borders.row_head),25,(255,255,0) )
    text.write('Visualization',(borders.col2_1[0]+win_W)/2,borders.row_head_1[1] + 0.35*(borders.row1_1[1]-borders.row_head),37,(255,255,0) )

    text.write('Dorsi Effort: '+str(int(dorsi_scale))+'%',bar1_x,borders.row1_1[1] + 0.8*(borders.row2_1[1]-borders.row1_1[1]),20,(255,255,0) )
    text.write('Plantar Effort: '+str(int(plantar_scale))+'%',bar2_x,borders.row1_1[1] + 0.8*(borders.row2_1[1]-borders.row1_1[1]),20,(255,255,0) )

    text.write('Status: '+dorsi_string, bar1_x, (borders.row2_1[1]+win_H)/2,30,(0,255,255) )
    text.write('Status: '+plantar_string, bar2_x, (borders.row2_1[1]+win_H)/2,30,(0,255,255) )
    text.write('Movement: '+movement_string, (borders.col2_1[0]+win_W)/2, (borders.row2_1[1]+win_H)/2,30,(255,0,255) )
    
    pg.display.update()
    pg.time.delay(20)

