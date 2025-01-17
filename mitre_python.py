from mitreattack.stix20 import MitreAttackData

mitre_attack_data = MitreAttackData("enterprise-attack.json")
technique = mitre_attack_data.get_object_by_attack_id('T1134', 'attack-pattern')