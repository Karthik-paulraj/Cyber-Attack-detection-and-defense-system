from dataclasses import dataclass

@dataclass

class Alert:
	
	time : str
	severity : str
	attack : str
	source : str
	destination : str
	message : str
	

