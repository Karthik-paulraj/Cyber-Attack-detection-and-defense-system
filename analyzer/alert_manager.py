from alert import Alert
from datetime import datetime

class AlertManagaer:
	
	def __init__(self):
		self.alerts = []
	
	
	def create_alert( self , severity , attack ,source,destination , message):
		
		alert = Alert(
			time = datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
		
			severity = severity  ,
		
			attack = attack ,
		
			source = source,
		
			destination = destination ,
		
			message = message )
		self.alerts.append(alert)
		
		return alert
		
		
	def show(self):

        	print("\n")

        	print("="*70)

        	print("SECURITY ALERTS")

        	print("="*70)

        	if len(self.alerts)==0:

            		print("No Alerts.")

            		return

        	for alert in self.alerts:

            		print(f"""
Time        : {alert.time}
Severity    : {alert.severity}
Attack      : {alert.attack}
Source      : {alert.source}
Destination : {alert.destination}
Message     : {alert.message}
{"="*70}
""")
