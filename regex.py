# -*- coding: latin-1 -*-

web_regex = "(?i)\\b((?:(https?)?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'\".,<>?«»“”‘’]))"

# Nomes retorna domini i si porta el protocol davant, per si es vol reduir el nombre de FP
simple_regex = 'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
