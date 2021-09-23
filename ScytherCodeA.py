usertype
Timestamp,Biometric,PUF,SK;
hashfunction H;
const XOR:Function;
const ADD:Function;
const MUL:Function;
const GEN:Function; 
const BFIu,BFGu,Dc,Bc,T1,
T2,IDc,Rc-as,Hc,Rc,T3,T4,
PWu,PWu',
Ec,RANu,Ku,Lbs,
T5,Rbs-u,RAN,CBc,BIDr,IDu,
Ras,Tbc,Obc,Nbc,Tbc,Tcb,
Rbc,Sc,Rcb,SKb-c,C1,XSs,
ZSs,R1,SRs,SIDp,CIDq,
SKe-v,SKbs-as;
const ADD:Function;
protocol SmartSociety(User, Cloud, BaseStation)
{
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
role User{
const IDu; #IDu is the user identity
const PWu; #user password
const BFu; #user biometric information
fresh Ras; #random number
send_!4(User,Cloud,IDu); #user sends the user identity to the cloud
macro BFu=H(BFIu,BFGu); #biometric function
send_!5(User,Cloud,H(IDu, BFIu)); #user sends the user identity and biometric values to the cloud
macro BFIu'=H(BFu,BFGu); #biometric ID 
macro Dc'=H(XOR(IDu,PWu),BFIu');
match(Dc', Dc); #verify by matching the constraints
macro Ac'=XOR(Bc,H(IDu,H(IDu,BFIu)));
macro Fu=H(IDu,Ac',Ras,T1);
macro Ras-c=XOR (Ras ,H(Ac',T1));
macro Gu=H(IDu,Ac');
send_!6(User,Cloud,Fu,Ras-c,IDu,T1,Gu); #user sends the parameters to the cloud
recv_!7(Cloud,User,Hc,Rc-as,IDc,T2);
macro Rc'=ADD(Ras,Ras-c);
macro Hc'=H(IDc,IDu,Ac',BFIu',Rc',T2);
match(Hc', Hc); #verify by matching the constraints
macro SKe-v = H(IDc,IDu,Ras,Rc );
claim_User(User,Niagree); #non-injective agreement
claim_User(User, Nisynch); #non-injective synchronization
claim_User(User,Secret,PWu); #password secrecy
claim_User(User,Secret, SKe-v); #session key secrecy         
#The Non-injective Synchronization (Ni-Agree) property requires sending and
#receiving events are executed by the runs mentioned by the cast
#function and is implemented in the correct order and with the same contents.
#The Non-injective Agreement (Ni-Agree) has claimed that the sender and 
#the receiver both agree upon the values of the variables that 
#are exchanged in between and the analysis results validate the claim’s correctness.     
}  
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
role Cloud{
const Sc;
recv_!1(BaseStation,Cloud,BIDr);
const IDc;
fresh Rc;
macro BSr=H(BIDr,Sc);
send_!2(Cloud,BaseStation,BSr);
recv_!4(User,Cloud,IDu); #cloud receives the user identity 
recv_!5(User,Cloud,H(IDu, BFIu)); #cloud receives the user identity and biometric values
macro Ac=H(H(IDu,BFIu),Sc);
macro Bc=XOR(Ac, H(IDu,H(IDu,BFIu)));
macro Dc=H(XOR(IDu,PWu),BFIu);
macro CBc=H(IDu,BIDr,BSr);
macro Ec=XOR(CBc,H(PWu,BFGu));
recv_!6(User,Cloud,Fu,Ras-c,IDu,T1,Gu); #cloud receives the parameters from the user
macro Ac=H(H(IDu,BFIu),Sc);
macro Ras'=XOR(Ras-c, H(Ac,T1));
macro Fu'=H(IDu,Ac,Ras',T1);
match(Fu', Fu); #verify by matching the constraints
macro Hc=H(IDc,IDu,Ac,BFIu,Rc,T2);
macro Rc-as=XOR(Ras',Rc);
send_!7(Cloud,User,Hc,Rc-as,IDc,T2); #cloud sends the computed parameters to the user
macro  SKe-v = H(IDc,IDu,Ras,Rc );
claim_Cloud(Cloud,Niagree); #non-injective agreement
claim_ Cloud (Cloud, Nisynch);#non-injective synchronization
claim_ Cloud (Cloud,Secret, SKe-v); #session key secrecy
}
}
