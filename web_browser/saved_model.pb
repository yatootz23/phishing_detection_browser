??
??
B
AssignVariableOp
resource
value"dtype"
dtypetype?
~
BiasAdd

value"T	
bias"T
output"T" 
Ttype:
2	"-
data_formatstringNHWC:
NHWCNCHW
8
Const
output"dtype"
valuetensor"
dtypetype
?
Conv2D

input"T
filter"T
output"T"
Ttype:	
2"
strides	list(int)"
use_cudnn_on_gpubool(",
paddingstring:
SAMEVALIDEXPLICIT""
explicit_paddings	list(int)
 "-
data_formatstringNHWC:
NHWCNCHW" 
	dilations	list(int)

W

ExpandDims

input"T
dim"Tdim
output"T"	
Ttype"
Tdimtype0:
2	
.
Identity

input"T
output"T"	
Ttype
q
MatMul
a"T
b"T
product"T"
transpose_abool( "
transpose_bbool( "
Ttype:

2	
?
MaxPool

input"T
output"T"
Ttype0:
2	"
ksize	list(int)(0"
strides	list(int)(0",
paddingstring:
SAMEVALIDEXPLICIT""
explicit_paddings	list(int)
 ":
data_formatstringNHWC:
NHWCNCHWNCHW_VECT_C
e
MergeV2Checkpoints
checkpoint_prefixes
destination_prefix"
delete_old_dirsbool(?

NoOp
M
Pack
values"T*N
output"T"
Nint(0"	
Ttype"
axisint 
C
Placeholder
output"dtype"
dtypetype"
shapeshape:
@
ReadVariableOp
resource
value"dtype"
dtypetype?
E
Relu
features"T
activations"T"
Ttype:
2	
[
Reshape
tensor"T
shape"Tshape
output"T"	
Ttype"
Tshapetype0:
2	
o
	RestoreV2

prefix
tensor_names
shape_and_slices
tensors2dtypes"
dtypes
list(type)(0?
l
SaveV2

prefix
tensor_names
shape_and_slices
tensors2dtypes"
dtypes
list(type)(0?
?
Select
	condition

t"T
e"T
output"T"	
Ttype
H
ShardedFilename
basename	
shard

num_shards
filename
9
Softmax
logits"T
softmax"T"
Ttype:
2
N
Squeeze

input"T
output"T"	
Ttype"
squeeze_dims	list(int)
 (
?
StatefulPartitionedCall
args2Tin
output2Tout"
Tin
list(type)("
Tout
list(type)("	
ffunc"
configstring "
config_protostring "
executor_typestring ?
@
StaticRegexFullMatch	
input

output
"
patternstring
N

StringJoin
inputs*N

output"
Nint(0"
	separatorstring 
?
VarHandleOp
resource"
	containerstring "
shared_namestring "
dtypetype"
shapeshape"#
allowed_deviceslist(string)
 ?"serve*2.5.02v2.5.0-rc3-213-ga4dfb8d1a718??
z
conv1d/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*
shared_nameconv1d/kernel
s
!conv1d/kernel/Read/ReadVariableOpReadVariableOpconv1d/kernel*"
_output_shapes
:(*
dtype0
n
conv1d/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*
shared_nameconv1d/bias
g
conv1d/bias/Read/ReadVariableOpReadVariableOpconv1d/bias*
_output_shapes
:(*
dtype0
z
CONV_1/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*
shared_nameCONV_1/kernel
s
!CONV_1/kernel/Read/ReadVariableOpReadVariableOpCONV_1/kernel*"
_output_shapes
:(*
dtype0
n
CONV_1/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape:*
shared_nameCONV_1/bias
g
CONV_1/bias/Read/ReadVariableOpReadVariableOpCONV_1/bias*
_output_shapes
:*
dtype0
z
CONV_2/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape:*
shared_nameCONV_2/kernel
s
!CONV_2/kernel/Read/ReadVariableOpReadVariableOpCONV_2/kernel*"
_output_shapes
:*
dtype0
n
CONV_2/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape:*
shared_nameCONV_2/bias
g
CONV_2/bias/Read/ReadVariableOpReadVariableOpCONV_2/bias*
_output_shapes
:*
dtype0
z
CONV_3/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape:*
shared_nameCONV_3/kernel
s
!CONV_3/kernel/Read/ReadVariableOpReadVariableOpCONV_3/kernel*"
_output_shapes
:*
dtype0
n
CONV_3/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape:*
shared_nameCONV_3/bias
g
CONV_3/bias/Read/ReadVariableOpReadVariableOpCONV_3/bias*
_output_shapes
:*
dtype0
z
CONV_4/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_nameCONV_4/kernel
s
!CONV_4/kernel/Read/ReadVariableOpReadVariableOpCONV_4/kernel*"
_output_shapes
: *
dtype0
n
CONV_4/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_nameCONV_4/bias
g
CONV_4/bias/Read/ReadVariableOpReadVariableOpCONV_4/bias*
_output_shapes
: *
dtype0
y
DENSE_1/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape:	?@*
shared_nameDENSE_1/kernel
r
"DENSE_1/kernel/Read/ReadVariableOpReadVariableOpDENSE_1/kernel*
_output_shapes
:	?@*
dtype0
p
DENSE_1/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape:@*
shared_nameDENSE_1/bias
i
 DENSE_1/bias/Read/ReadVariableOpReadVariableOpDENSE_1/bias*
_output_shapes
:@*
dtype0
v
OUTPUT/kernelVarHandleOp*
_output_shapes
: *
dtype0*
shape
:@*
shared_nameOUTPUT/kernel
o
!OUTPUT/kernel/Read/ReadVariableOpReadVariableOpOUTPUT/kernel*
_output_shapes

:@*
dtype0
n
OUTPUT/biasVarHandleOp*
_output_shapes
: *
dtype0*
shape:*
shared_nameOUTPUT/bias
g
OUTPUT/bias/Read/ReadVariableOpReadVariableOpOUTPUT/bias*
_output_shapes
:*
dtype0
f
	Adam/iterVarHandleOp*
_output_shapes
: *
dtype0	*
shape: *
shared_name	Adam/iter
_
Adam/iter/Read/ReadVariableOpReadVariableOp	Adam/iter*
_output_shapes
: *
dtype0	
j
Adam/beta_1VarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_nameAdam/beta_1
c
Adam/beta_1/Read/ReadVariableOpReadVariableOpAdam/beta_1*
_output_shapes
: *
dtype0
j
Adam/beta_2VarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_nameAdam/beta_2
c
Adam/beta_2/Read/ReadVariableOpReadVariableOpAdam/beta_2*
_output_shapes
: *
dtype0
h

Adam/decayVarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_name
Adam/decay
a
Adam/decay/Read/ReadVariableOpReadVariableOp
Adam/decay*
_output_shapes
: *
dtype0
x
Adam/learning_rateVarHandleOp*
_output_shapes
: *
dtype0*
shape: *#
shared_nameAdam/learning_rate
q
&Adam/learning_rate/Read/ReadVariableOpReadVariableOpAdam/learning_rate*
_output_shapes
: *
dtype0
^
totalVarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_nametotal
W
total/Read/ReadVariableOpReadVariableOptotal*
_output_shapes
: *
dtype0
^
countVarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_namecount
W
count/Read/ReadVariableOpReadVariableOpcount*
_output_shapes
: *
dtype0
b
total_1VarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_name	total_1
[
total_1/Read/ReadVariableOpReadVariableOptotal_1*
_output_shapes
: *
dtype0
b
count_1VarHandleOp*
_output_shapes
: *
dtype0*
shape: *
shared_name	count_1
[
count_1/Read/ReadVariableOpReadVariableOpcount_1*
_output_shapes
: *
dtype0
?
Adam/conv1d/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*%
shared_nameAdam/conv1d/kernel/m
?
(Adam/conv1d/kernel/m/Read/ReadVariableOpReadVariableOpAdam/conv1d/kernel/m*"
_output_shapes
:(*
dtype0
|
Adam/conv1d/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*#
shared_nameAdam/conv1d/bias/m
u
&Adam/conv1d/bias/m/Read/ReadVariableOpReadVariableOpAdam/conv1d/bias/m*
_output_shapes
:(*
dtype0
?
Adam/CONV_1/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*%
shared_nameAdam/CONV_1/kernel/m
?
(Adam/CONV_1/kernel/m/Read/ReadVariableOpReadVariableOpAdam/CONV_1/kernel/m*"
_output_shapes
:(*
dtype0
|
Adam/CONV_1/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/CONV_1/bias/m
u
&Adam/CONV_1/bias/m/Read/ReadVariableOpReadVariableOpAdam/CONV_1/bias/m*
_output_shapes
:*
dtype0
?
Adam/CONV_2/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:*%
shared_nameAdam/CONV_2/kernel/m
?
(Adam/CONV_2/kernel/m/Read/ReadVariableOpReadVariableOpAdam/CONV_2/kernel/m*"
_output_shapes
:*
dtype0
|
Adam/CONV_2/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/CONV_2/bias/m
u
&Adam/CONV_2/bias/m/Read/ReadVariableOpReadVariableOpAdam/CONV_2/bias/m*
_output_shapes
:*
dtype0
?
Adam/CONV_3/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:*%
shared_nameAdam/CONV_3/kernel/m
?
(Adam/CONV_3/kernel/m/Read/ReadVariableOpReadVariableOpAdam/CONV_3/kernel/m*"
_output_shapes
:*
dtype0
|
Adam/CONV_3/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/CONV_3/bias/m
u
&Adam/CONV_3/bias/m/Read/ReadVariableOpReadVariableOpAdam/CONV_3/bias/m*
_output_shapes
:*
dtype0
?
Adam/CONV_4/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape: *%
shared_nameAdam/CONV_4/kernel/m
?
(Adam/CONV_4/kernel/m/Read/ReadVariableOpReadVariableOpAdam/CONV_4/kernel/m*"
_output_shapes
: *
dtype0
|
Adam/CONV_4/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape: *#
shared_nameAdam/CONV_4/bias/m
u
&Adam/CONV_4/bias/m/Read/ReadVariableOpReadVariableOpAdam/CONV_4/bias/m*
_output_shapes
: *
dtype0
?
Adam/DENSE_1/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:	?@*&
shared_nameAdam/DENSE_1/kernel/m
?
)Adam/DENSE_1/kernel/m/Read/ReadVariableOpReadVariableOpAdam/DENSE_1/kernel/m*
_output_shapes
:	?@*
dtype0
~
Adam/DENSE_1/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:@*$
shared_nameAdam/DENSE_1/bias/m
w
'Adam/DENSE_1/bias/m/Read/ReadVariableOpReadVariableOpAdam/DENSE_1/bias/m*
_output_shapes
:@*
dtype0
?
Adam/OUTPUT/kernel/mVarHandleOp*
_output_shapes
: *
dtype0*
shape
:@*%
shared_nameAdam/OUTPUT/kernel/m
}
(Adam/OUTPUT/kernel/m/Read/ReadVariableOpReadVariableOpAdam/OUTPUT/kernel/m*
_output_shapes

:@*
dtype0
|
Adam/OUTPUT/bias/mVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/OUTPUT/bias/m
u
&Adam/OUTPUT/bias/m/Read/ReadVariableOpReadVariableOpAdam/OUTPUT/bias/m*
_output_shapes
:*
dtype0
?
Adam/conv1d/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*%
shared_nameAdam/conv1d/kernel/v
?
(Adam/conv1d/kernel/v/Read/ReadVariableOpReadVariableOpAdam/conv1d/kernel/v*"
_output_shapes
:(*
dtype0
|
Adam/conv1d/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*#
shared_nameAdam/conv1d/bias/v
u
&Adam/conv1d/bias/v/Read/ReadVariableOpReadVariableOpAdam/conv1d/bias/v*
_output_shapes
:(*
dtype0
?
Adam/CONV_1/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:(*%
shared_nameAdam/CONV_1/kernel/v
?
(Adam/CONV_1/kernel/v/Read/ReadVariableOpReadVariableOpAdam/CONV_1/kernel/v*"
_output_shapes
:(*
dtype0
|
Adam/CONV_1/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/CONV_1/bias/v
u
&Adam/CONV_1/bias/v/Read/ReadVariableOpReadVariableOpAdam/CONV_1/bias/v*
_output_shapes
:*
dtype0
?
Adam/CONV_2/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:*%
shared_nameAdam/CONV_2/kernel/v
?
(Adam/CONV_2/kernel/v/Read/ReadVariableOpReadVariableOpAdam/CONV_2/kernel/v*"
_output_shapes
:*
dtype0
|
Adam/CONV_2/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/CONV_2/bias/v
u
&Adam/CONV_2/bias/v/Read/ReadVariableOpReadVariableOpAdam/CONV_2/bias/v*
_output_shapes
:*
dtype0
?
Adam/CONV_3/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:*%
shared_nameAdam/CONV_3/kernel/v
?
(Adam/CONV_3/kernel/v/Read/ReadVariableOpReadVariableOpAdam/CONV_3/kernel/v*"
_output_shapes
:*
dtype0
|
Adam/CONV_3/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/CONV_3/bias/v
u
&Adam/CONV_3/bias/v/Read/ReadVariableOpReadVariableOpAdam/CONV_3/bias/v*
_output_shapes
:*
dtype0
?
Adam/CONV_4/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape: *%
shared_nameAdam/CONV_4/kernel/v
?
(Adam/CONV_4/kernel/v/Read/ReadVariableOpReadVariableOpAdam/CONV_4/kernel/v*"
_output_shapes
: *
dtype0
|
Adam/CONV_4/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape: *#
shared_nameAdam/CONV_4/bias/v
u
&Adam/CONV_4/bias/v/Read/ReadVariableOpReadVariableOpAdam/CONV_4/bias/v*
_output_shapes
: *
dtype0
?
Adam/DENSE_1/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:	?@*&
shared_nameAdam/DENSE_1/kernel/v
?
)Adam/DENSE_1/kernel/v/Read/ReadVariableOpReadVariableOpAdam/DENSE_1/kernel/v*
_output_shapes
:	?@*
dtype0
~
Adam/DENSE_1/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:@*$
shared_nameAdam/DENSE_1/bias/v
w
'Adam/DENSE_1/bias/v/Read/ReadVariableOpReadVariableOpAdam/DENSE_1/bias/v*
_output_shapes
:@*
dtype0
?
Adam/OUTPUT/kernel/vVarHandleOp*
_output_shapes
: *
dtype0*
shape
:@*%
shared_nameAdam/OUTPUT/kernel/v
}
(Adam/OUTPUT/kernel/v/Read/ReadVariableOpReadVariableOpAdam/OUTPUT/kernel/v*
_output_shapes

:@*
dtype0
|
Adam/OUTPUT/bias/vVarHandleOp*
_output_shapes
: *
dtype0*
shape:*#
shared_nameAdam/OUTPUT/bias/v
u
&Adam/OUTPUT/bias/v/Read/ReadVariableOpReadVariableOpAdam/OUTPUT/bias/v*
_output_shapes
:*
dtype0

NoOpNoOp
?S
ConstConst"/device:CPU:0*
_output_shapes
: *
dtype0*?S
value?SB?S B?S
?
layer_with_weights-0
layer-0
layer_with_weights-1
layer-1
layer-2
layer_with_weights-2
layer-3
layer_with_weights-3
layer-4
layer_with_weights-4
layer-5
layer-6
layer-7
	layer-8

layer_with_weights-5

layer-9
layer-10
layer_with_weights-6
layer-11
	optimizer
regularization_losses
	variables
trainable_variables
	keras_api

signatures
h

kernel
bias
regularization_losses
	variables
trainable_variables
	keras_api
h

kernel
bias
regularization_losses
	variables
trainable_variables
	keras_api
R
regularization_losses
 	variables
!trainable_variables
"	keras_api
h

#kernel
$bias
%regularization_losses
&	variables
'trainable_variables
(	keras_api
h

)kernel
*bias
+regularization_losses
,	variables
-trainable_variables
.	keras_api
h

/kernel
0bias
1regularization_losses
2	variables
3trainable_variables
4	keras_api
R
5regularization_losses
6	variables
7trainable_variables
8	keras_api
R
9regularization_losses
:	variables
;trainable_variables
<	keras_api
R
=regularization_losses
>	variables
?trainable_variables
@	keras_api
h

Akernel
Bbias
Cregularization_losses
D	variables
Etrainable_variables
F	keras_api
R
Gregularization_losses
H	variables
Itrainable_variables
J	keras_api
h

Kkernel
Lbias
Mregularization_losses
N	variables
Otrainable_variables
P	keras_api
?
Qiter

Rbeta_1

Sbeta_2
	Tdecay
Ulearning_ratem?m?m?m?#m?$m?)m?*m?/m?0m?Am?Bm?Km?Lm?v?v?v?v?#v?$v?)v?*v?/v?0v?Av?Bv?Kv?Lv?
 
f
0
1
2
3
#4
$5
)6
*7
/8
09
A10
B11
K12
L13
f
0
1
2
3
#4
$5
)6
*7
/8
09
A10
B11
K12
L13
?
Vlayer_metrics
regularization_losses
Wmetrics
Xnon_trainable_variables
Ylayer_regularization_losses
	variables

Zlayers
trainable_variables
 
YW
VARIABLE_VALUEconv1d/kernel6layer_with_weights-0/kernel/.ATTRIBUTES/VARIABLE_VALUE
US
VARIABLE_VALUEconv1d/bias4layer_with_weights-0/bias/.ATTRIBUTES/VARIABLE_VALUE
 

0
1

0
1
?
[layer_metrics
regularization_losses
\metrics
]non_trainable_variables
^layer_regularization_losses
	variables

_layers
trainable_variables
YW
VARIABLE_VALUECONV_1/kernel6layer_with_weights-1/kernel/.ATTRIBUTES/VARIABLE_VALUE
US
VARIABLE_VALUECONV_1/bias4layer_with_weights-1/bias/.ATTRIBUTES/VARIABLE_VALUE
 

0
1

0
1
?
`layer_metrics
regularization_losses
ametrics
bnon_trainable_variables
clayer_regularization_losses
	variables

dlayers
trainable_variables
 
 
 
?
elayer_metrics
regularization_losses
fmetrics
gnon_trainable_variables
hlayer_regularization_losses
 	variables

ilayers
!trainable_variables
YW
VARIABLE_VALUECONV_2/kernel6layer_with_weights-2/kernel/.ATTRIBUTES/VARIABLE_VALUE
US
VARIABLE_VALUECONV_2/bias4layer_with_weights-2/bias/.ATTRIBUTES/VARIABLE_VALUE
 

#0
$1

#0
$1
?
jlayer_metrics
%regularization_losses
kmetrics
lnon_trainable_variables
mlayer_regularization_losses
&	variables

nlayers
'trainable_variables
YW
VARIABLE_VALUECONV_3/kernel6layer_with_weights-3/kernel/.ATTRIBUTES/VARIABLE_VALUE
US
VARIABLE_VALUECONV_3/bias4layer_with_weights-3/bias/.ATTRIBUTES/VARIABLE_VALUE
 

)0
*1

)0
*1
?
olayer_metrics
+regularization_losses
pmetrics
qnon_trainable_variables
rlayer_regularization_losses
,	variables

slayers
-trainable_variables
YW
VARIABLE_VALUECONV_4/kernel6layer_with_weights-4/kernel/.ATTRIBUTES/VARIABLE_VALUE
US
VARIABLE_VALUECONV_4/bias4layer_with_weights-4/bias/.ATTRIBUTES/VARIABLE_VALUE
 

/0
01

/0
01
?
tlayer_metrics
1regularization_losses
umetrics
vnon_trainable_variables
wlayer_regularization_losses
2	variables

xlayers
3trainable_variables
 
 
 
?
ylayer_metrics
5regularization_losses
zmetrics
{non_trainable_variables
|layer_regularization_losses
6	variables

}layers
7trainable_variables
 
 
 
?
~layer_metrics
9regularization_losses
metrics
?non_trainable_variables
 ?layer_regularization_losses
:	variables
?layers
;trainable_variables
 
 
 
?
?layer_metrics
=regularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
>	variables
?layers
?trainable_variables
ZX
VARIABLE_VALUEDENSE_1/kernel6layer_with_weights-5/kernel/.ATTRIBUTES/VARIABLE_VALUE
VT
VARIABLE_VALUEDENSE_1/bias4layer_with_weights-5/bias/.ATTRIBUTES/VARIABLE_VALUE
 

A0
B1

A0
B1
?
?layer_metrics
Cregularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
D	variables
?layers
Etrainable_variables
 
 
 
?
?layer_metrics
Gregularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
H	variables
?layers
Itrainable_variables
YW
VARIABLE_VALUEOUTPUT/kernel6layer_with_weights-6/kernel/.ATTRIBUTES/VARIABLE_VALUE
US
VARIABLE_VALUEOUTPUT/bias4layer_with_weights-6/bias/.ATTRIBUTES/VARIABLE_VALUE
 

K0
L1

K0
L1
?
?layer_metrics
Mregularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
N	variables
?layers
Otrainable_variables
HF
VARIABLE_VALUE	Adam/iter)optimizer/iter/.ATTRIBUTES/VARIABLE_VALUE
LJ
VARIABLE_VALUEAdam/beta_1+optimizer/beta_1/.ATTRIBUTES/VARIABLE_VALUE
LJ
VARIABLE_VALUEAdam/beta_2+optimizer/beta_2/.ATTRIBUTES/VARIABLE_VALUE
JH
VARIABLE_VALUE
Adam/decay*optimizer/decay/.ATTRIBUTES/VARIABLE_VALUE
ZX
VARIABLE_VALUEAdam/learning_rate2optimizer/learning_rate/.ATTRIBUTES/VARIABLE_VALUE
 

?0
?1
 
 
V
0
1
2
3
4
5
6
7
	8

9
10
11
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
8

?total

?count
?	variables
?	keras_api
I

?total

?count
?
_fn_kwargs
?	variables
?	keras_api
OM
VARIABLE_VALUEtotal4keras_api/metrics/0/total/.ATTRIBUTES/VARIABLE_VALUE
OM
VARIABLE_VALUEcount4keras_api/metrics/0/count/.ATTRIBUTES/VARIABLE_VALUE

?0
?1

?	variables
QO
VARIABLE_VALUEtotal_14keras_api/metrics/1/total/.ATTRIBUTES/VARIABLE_VALUE
QO
VARIABLE_VALUEcount_14keras_api/metrics/1/count/.ATTRIBUTES/VARIABLE_VALUE
 

?0
?1

?	variables
|z
VARIABLE_VALUEAdam/conv1d/kernel/mRlayer_with_weights-0/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/conv1d/bias/mPlayer_with_weights-0/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_1/kernel/mRlayer_with_weights-1/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_1/bias/mPlayer_with_weights-1/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_2/kernel/mRlayer_with_weights-2/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_2/bias/mPlayer_with_weights-2/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_3/kernel/mRlayer_with_weights-3/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_3/bias/mPlayer_with_weights-3/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_4/kernel/mRlayer_with_weights-4/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_4/bias/mPlayer_with_weights-4/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
}{
VARIABLE_VALUEAdam/DENSE_1/kernel/mRlayer_with_weights-5/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
yw
VARIABLE_VALUEAdam/DENSE_1/bias/mPlayer_with_weights-5/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/OUTPUT/kernel/mRlayer_with_weights-6/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/OUTPUT/bias/mPlayer_with_weights-6/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/conv1d/kernel/vRlayer_with_weights-0/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/conv1d/bias/vPlayer_with_weights-0/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_1/kernel/vRlayer_with_weights-1/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_1/bias/vPlayer_with_weights-1/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_2/kernel/vRlayer_with_weights-2/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_2/bias/vPlayer_with_weights-2/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_3/kernel/vRlayer_with_weights-3/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_3/bias/vPlayer_with_weights-3/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/CONV_4/kernel/vRlayer_with_weights-4/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/CONV_4/bias/vPlayer_with_weights-4/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
}{
VARIABLE_VALUEAdam/DENSE_1/kernel/vRlayer_with_weights-5/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
yw
VARIABLE_VALUEAdam/DENSE_1/bias/vPlayer_with_weights-5/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
|z
VARIABLE_VALUEAdam/OUTPUT/kernel/vRlayer_with_weights-6/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
xv
VARIABLE_VALUEAdam/OUTPUT/bias/vPlayer_with_weights-6/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUE
?
serving_default_conv1d_inputPlaceholder*+
_output_shapes
:?????????*
dtype0* 
shape:?????????
?
StatefulPartitionedCallStatefulPartitionedCallserving_default_conv1d_inputconv1d/kernelconv1d/biasCONV_1/kernelCONV_1/biasCONV_2/kernelCONV_2/biasCONV_3/kernelCONV_3/biasCONV_4/kernelCONV_4/biasDENSE_1/kernelDENSE_1/biasOUTPUT/kernelOUTPUT/bias*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*0
_read_only_resource_inputs
	
*-
config_proto

CPU

GPU 2J 8? *-
f(R&
$__inference_signature_wrapper_160372
O
saver_filenamePlaceholder*
_output_shapes
: *
dtype0*
shape: 
?
StatefulPartitionedCall_1StatefulPartitionedCallsaver_filename!conv1d/kernel/Read/ReadVariableOpconv1d/bias/Read/ReadVariableOp!CONV_1/kernel/Read/ReadVariableOpCONV_1/bias/Read/ReadVariableOp!CONV_2/kernel/Read/ReadVariableOpCONV_2/bias/Read/ReadVariableOp!CONV_3/kernel/Read/ReadVariableOpCONV_3/bias/Read/ReadVariableOp!CONV_4/kernel/Read/ReadVariableOpCONV_4/bias/Read/ReadVariableOp"DENSE_1/kernel/Read/ReadVariableOp DENSE_1/bias/Read/ReadVariableOp!OUTPUT/kernel/Read/ReadVariableOpOUTPUT/bias/Read/ReadVariableOpAdam/iter/Read/ReadVariableOpAdam/beta_1/Read/ReadVariableOpAdam/beta_2/Read/ReadVariableOpAdam/decay/Read/ReadVariableOp&Adam/learning_rate/Read/ReadVariableOptotal/Read/ReadVariableOpcount/Read/ReadVariableOptotal_1/Read/ReadVariableOpcount_1/Read/ReadVariableOp(Adam/conv1d/kernel/m/Read/ReadVariableOp&Adam/conv1d/bias/m/Read/ReadVariableOp(Adam/CONV_1/kernel/m/Read/ReadVariableOp&Adam/CONV_1/bias/m/Read/ReadVariableOp(Adam/CONV_2/kernel/m/Read/ReadVariableOp&Adam/CONV_2/bias/m/Read/ReadVariableOp(Adam/CONV_3/kernel/m/Read/ReadVariableOp&Adam/CONV_3/bias/m/Read/ReadVariableOp(Adam/CONV_4/kernel/m/Read/ReadVariableOp&Adam/CONV_4/bias/m/Read/ReadVariableOp)Adam/DENSE_1/kernel/m/Read/ReadVariableOp'Adam/DENSE_1/bias/m/Read/ReadVariableOp(Adam/OUTPUT/kernel/m/Read/ReadVariableOp&Adam/OUTPUT/bias/m/Read/ReadVariableOp(Adam/conv1d/kernel/v/Read/ReadVariableOp&Adam/conv1d/bias/v/Read/ReadVariableOp(Adam/CONV_1/kernel/v/Read/ReadVariableOp&Adam/CONV_1/bias/v/Read/ReadVariableOp(Adam/CONV_2/kernel/v/Read/ReadVariableOp&Adam/CONV_2/bias/v/Read/ReadVariableOp(Adam/CONV_3/kernel/v/Read/ReadVariableOp&Adam/CONV_3/bias/v/Read/ReadVariableOp(Adam/CONV_4/kernel/v/Read/ReadVariableOp&Adam/CONV_4/bias/v/Read/ReadVariableOp)Adam/DENSE_1/kernel/v/Read/ReadVariableOp'Adam/DENSE_1/bias/v/Read/ReadVariableOp(Adam/OUTPUT/kernel/v/Read/ReadVariableOp&Adam/OUTPUT/bias/v/Read/ReadVariableOpConst*@
Tin9
725	*
Tout
2*
_collective_manager_ids
 *
_output_shapes
: * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *(
f#R!
__inference__traced_save_161143
?	
StatefulPartitionedCall_2StatefulPartitionedCallsaver_filenameconv1d/kernelconv1d/biasCONV_1/kernelCONV_1/biasCONV_2/kernelCONV_2/biasCONV_3/kernelCONV_3/biasCONV_4/kernelCONV_4/biasDENSE_1/kernelDENSE_1/biasOUTPUT/kernelOUTPUT/bias	Adam/iterAdam/beta_1Adam/beta_2
Adam/decayAdam/learning_ratetotalcounttotal_1count_1Adam/conv1d/kernel/mAdam/conv1d/bias/mAdam/CONV_1/kernel/mAdam/CONV_1/bias/mAdam/CONV_2/kernel/mAdam/CONV_2/bias/mAdam/CONV_3/kernel/mAdam/CONV_3/bias/mAdam/CONV_4/kernel/mAdam/CONV_4/bias/mAdam/DENSE_1/kernel/mAdam/DENSE_1/bias/mAdam/OUTPUT/kernel/mAdam/OUTPUT/bias/mAdam/conv1d/kernel/vAdam/conv1d/bias/vAdam/CONV_1/kernel/vAdam/CONV_1/bias/vAdam/CONV_2/kernel/vAdam/CONV_2/bias/vAdam/CONV_3/kernel/vAdam/CONV_3/bias/vAdam/CONV_4/kernel/vAdam/CONV_4/bias/vAdam/DENSE_1/kernel/vAdam/DENSE_1/bias/vAdam/OUTPUT/kernel/vAdam/OUTPUT/bias/v*?
Tin8
624*
Tout
2*
_collective_manager_ids
 *
_output_shapes
: * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *+
f&R$
"__inference__traced_restore_161306??
?
?
B__inference_conv1d_layer_call_and_return_conditional_losses_160696

inputsA
+conv1d_expanddims_1_readvariableop_resource:(-
biasadd_readvariableop_resource:(
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOp?,conv1d/kernel/Regularizer/Abs/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????(*
paddingVALID*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????(*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:(*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????(2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????(2
Relu?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*+
_output_shapes
:?????????(2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?
?
'__inference_OUTPUT_layer_call_fn_160934

inputs
unknown:@
	unknown_0:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_OUTPUT_layer_call_and_return_conditional_losses_1598502
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:?????????@: : 22
StatefulPartitionedCallStatefulPartitionedCall:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
?
__inference_loss_fn_2_160967I
6dense_1_kernel_regularizer_abs_readvariableop_resource:	?@
identity??-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp6dense_1_kernel_regularizer_abs_readvariableop_resource*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentity"DENSE_1/kernel/Regularizer/mul:z:0.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp*
T0*
_output_shapes
: 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*
_input_shapes
: 2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp
?
?
/__inference_Proposed_Model_layer_call_fn_160668

inputs
unknown:(
	unknown_0:(
	unknown_1:(
	unknown_2:
	unknown_3:
	unknown_4:
	unknown_5:
	unknown_6:
	unknown_7: 
	unknown_8: 
	unknown_9:	?@

unknown_10:@

unknown_11:@

unknown_12:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0	unknown_1	unknown_2	unknown_3	unknown_4	unknown_5	unknown_6	unknown_7	unknown_8	unknown_9
unknown_10
unknown_11
unknown_12*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*0
_read_only_resource_inputs
	
*-
config_proto

CPU

GPU 2J 8? *S
fNRL
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_1601252
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?
?
B__inference_CONV_1_layer_call_and_return_conditional_losses_159714

inputsA
+conv1d_expanddims_1_readvariableop_resource:(-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????(2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????*
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????2
Relu?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????(: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????(
 
_user_specified_nameinputs
?
?
'__inference_CONV_3_layer_call_fn_160792

inputs
unknown:
	unknown_0:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_3_layer_call_and_return_conditional_losses_1597652
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*+
_output_shapes
:?????????	2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
c
*__inference_DROPOUT_2_layer_call_fn_160914

inputs
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_1599362
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*&
_input_shapes
:?????????@22
StatefulPartitionedCallStatefulPartitionedCall:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
?
B__inference_CONV_4_layer_call_and_return_conditional_losses_159787

inputsA
+conv1d_expanddims_1_readvariableop_resource: -
biasadd_readvariableop_resource: 
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
: *
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
: 2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	 *
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????	 *
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
: *
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	 2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????	 2
Relu?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????	 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
?
B__inference_CONV_2_layer_call_and_return_conditional_losses_159743

inputsA
+conv1d_expanddims_1_readvariableop_resource:-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
Relu?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????	2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?P
?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160251
conv1d_input#
conv1d_160192:(
conv1d_160194:(#
conv_1_160197:(
conv_1_160199:#
conv_2_160203:
conv_2_160205:#
conv_3_160208:
conv_3_160210:#
conv_4_160213: 
conv_4_160215: !
dense_1_160221:	?@
dense_1_160223:@
output_160227:@
output_160229:
identity??CONV_1/StatefulPartitionedCall?CONV_2/StatefulPartitionedCall?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?CONV_3/StatefulPartitionedCall?CONV_4/StatefulPartitionedCall?DENSE_1/StatefulPartitionedCall?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?OUTPUT/StatefulPartitionedCall?conv1d/StatefulPartitionedCall?,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/StatefulPartitionedCallStatefulPartitionedCallconv1d_inputconv1d_160192conv1d_160194*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????(*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_conv1d_layer_call_and_return_conditional_losses_1596922 
conv1d/StatefulPartitionedCall?
CONV_1/StatefulPartitionedCallStatefulPartitionedCall'conv1d/StatefulPartitionedCall:output:0conv_1_160197conv_1_160199*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_1_layer_call_and_return_conditional_losses_1597142 
CONV_1/StatefulPartitionedCall?
POOLING_1/PartitionedCallPartitionedCall'CONV_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_1_layer_call_and_return_conditional_losses_1596422
POOLING_1/PartitionedCall?
CONV_2/StatefulPartitionedCallStatefulPartitionedCall"POOLING_1/PartitionedCall:output:0conv_2_160203conv_2_160205*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_2_layer_call_and_return_conditional_losses_1597432 
CONV_2/StatefulPartitionedCall?
CONV_3/StatefulPartitionedCallStatefulPartitionedCall'CONV_2/StatefulPartitionedCall:output:0conv_3_160208conv_3_160210*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_3_layer_call_and_return_conditional_losses_1597652 
CONV_3/StatefulPartitionedCall?
CONV_4/StatefulPartitionedCallStatefulPartitionedCall'CONV_3/StatefulPartitionedCall:output:0conv_4_160213conv_4_160215*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	 *$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_4_layer_call_and_return_conditional_losses_1597872 
CONV_4/StatefulPartitionedCall?
POOLING_2/PartitionedCallPartitionedCall'CONV_4/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_2_layer_call_and_return_conditional_losses_1596572
POOLING_2/PartitionedCall?
DROPOUT_1/PartitionedCallPartitionedCall"POOLING_2/PartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_1597992
DROPOUT_1/PartitionedCall?
FC/PartitionedCallPartitionedCall"DROPOUT_1/PartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *(
_output_shapes
:??????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *G
fBR@
>__inference_FC_layer_call_and_return_conditional_losses_1598072
FC/PartitionedCall?
DENSE_1/StatefulPartitionedCallStatefulPartitionedCallFC/PartitionedCall:output:0dense_1_160221dense_1_160223*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *L
fGRE
C__inference_DENSE_1_layer_call_and_return_conditional_losses_1598262!
DENSE_1/StatefulPartitionedCall?
DROPOUT_2/PartitionedCallPartitionedCall(DENSE_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_1598372
DROPOUT_2/PartitionedCall?
OUTPUT/StatefulPartitionedCallStatefulPartitionedCall"DROPOUT_2/PartitionedCall:output:0output_160227output_160229*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_OUTPUT_layer_call_and_return_conditional_losses_1598502 
OUTPUT/StatefulPartitionedCall?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv1d_160192*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv_2_160203*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpdense_1_160221*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentity'OUTPUT/StatefulPartitionedCall:output:0^CONV_1/StatefulPartitionedCall^CONV_2/StatefulPartitionedCall-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp^CONV_3/StatefulPartitionedCall^CONV_4/StatefulPartitionedCall ^DENSE_1/StatefulPartitionedCall.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp^OUTPUT/StatefulPartitionedCall^conv1d/StatefulPartitionedCall-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2@
CONV_1/StatefulPartitionedCallCONV_1/StatefulPartitionedCall2@
CONV_2/StatefulPartitionedCallCONV_2/StatefulPartitionedCall2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2@
CONV_3/StatefulPartitionedCallCONV_3/StatefulPartitionedCall2@
CONV_4/StatefulPartitionedCallCONV_4/StatefulPartitionedCall2B
DENSE_1/StatefulPartitionedCallDENSE_1/StatefulPartitionedCall2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2@
OUTPUT/StatefulPartitionedCallOUTPUT/StatefulPartitionedCall2@
conv1d/StatefulPartitionedCallconv1d/StatefulPartitionedCall2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:Y U
+
_output_shapes
:?????????
&
_user_specified_nameconv1d_input
?
?
'__inference_CONV_2_layer_call_fn_160767

inputs
unknown:
	unknown_0:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_2_layer_call_and_return_conditional_losses_1597432
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*+
_output_shapes
:?????????	2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
?
C__inference_DENSE_1_layer_call_and_return_conditional_losses_160878

inputs1
matmul_readvariableop_resource:	?@-
biasadd_readvariableop_resource:@
identity??BiasAdd/ReadVariableOp?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?MatMul/ReadVariableOp?
MatMul/ReadVariableOpReadVariableOpmatmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02
MatMul/ReadVariableOps
MatMulMatMulinputsMatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
MatMul?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:@*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddMatMul:product:0BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2	
BiasAddX
ReluReluBiasAdd:output:0*
T0*'
_output_shapes
:?????????@2
Relu?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpmatmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp^MatMul/ReadVariableOp*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*+
_input_shapes
:??????????: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2.
MatMul/ReadVariableOpMatMul/ReadVariableOp:P L
(
_output_shapes
:??????????
 
_user_specified_nameinputs
?
a
E__inference_POOLING_1_layer_call_and_return_conditional_losses_159642

inputs
identityb
ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2
ExpandDims/dim?

ExpandDims
ExpandDimsinputsExpandDims/dim:output:0*
T0*A
_output_shapes/
-:+???????????????????????????2

ExpandDims?
MaxPoolMaxPoolExpandDims:output:0*A
_output_shapes/
-:+???????????????????????????*
ksize
*
paddingVALID*
strides
2	
MaxPool?
SqueezeSqueezeMaxPool:output:0*
T0*=
_output_shapes+
):'???????????????????????????*
squeeze_dims
2	
Squeezez
IdentityIdentitySqueeze:output:0*
T0*=
_output_shapes+
):'???????????????????????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*<
_input_shapes+
):'???????????????????????????:e a
=
_output_shapes+
):'???????????????????????????
 
_user_specified_nameinputs
?
d
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_159936

inputs
identity?c
dropout/ConstConst*
_output_shapes
: *
dtype0*
valueB
 *   @2
dropout/Consts
dropout/MulMulinputsdropout/Const:output:0*
T0*'
_output_shapes
:?????????@2
dropout/MulT
dropout/ShapeShapeinputs*
T0*
_output_shapes
:2
dropout/Shape?
$dropout/random_uniform/RandomUniformRandomUniformdropout/Shape:output:0*
T0*'
_output_shapes
:?????????@*
dtype02&
$dropout/random_uniform/RandomUniformu
dropout/GreaterEqual/yConst*
_output_shapes
: *
dtype0*
valueB
 *   ?2
dropout/GreaterEqual/y?
dropout/GreaterEqualGreaterEqual-dropout/random_uniform/RandomUniform:output:0dropout/GreaterEqual/y:output:0*
T0*'
_output_shapes
:?????????@2
dropout/GreaterEqual
dropout/CastCastdropout/GreaterEqual:z:0*

DstT0*

SrcT0
*'
_output_shapes
:?????????@2
dropout/Castz
dropout/Mul_1Muldropout/Mul:z:0dropout/Cast:y:0*
T0*'
_output_shapes
:?????????@2
dropout/Mul_1e
IdentityIdentitydropout/Mul_1:z:0*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*&
_input_shapes
:?????????@:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
Z
>__inference_FC_layer_call_and_return_conditional_losses_160850

inputs
identity_
ConstConst*
_output_shapes
:*
dtype0*
valueB"?????   2
Consth
ReshapeReshapeinputsConst:output:0*
T0*(
_output_shapes
:??????????2	
Reshapee
IdentityIdentityReshape:output:0*
T0*(
_output_shapes
:??????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
?
__inference_loss_fn_0_160945K
5conv1d_kernel_regularizer_abs_readvariableop_resource:(
identity??,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp5conv1d_kernel_regularizer_abs_readvariableop_resource*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
IdentityIdentity!conv1d/kernel/Regularizer/mul:z:0-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*
_output_shapes
: 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*
_input_shapes
: 2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp
?
F
*__inference_POOLING_2_layer_call_fn_159663

inputs
identity?
PartitionedCallPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *=
_output_shapes+
):'???????????????????????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_2_layer_call_and_return_conditional_losses_1596572
PartitionedCall?
IdentityIdentityPartitionedCall:output:0*
T0*=
_output_shapes+
):'???????????????????????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*<
_input_shapes+
):'???????????????????????????:e a
=
_output_shapes+
):'???????????????????????????
 
_user_specified_nameinputs
??
?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160480

inputsH
2conv1d_conv1d_expanddims_1_readvariableop_resource:(4
&conv1d_biasadd_readvariableop_resource:(H
2conv_1_conv1d_expanddims_1_readvariableop_resource:(4
&conv_1_biasadd_readvariableop_resource:H
2conv_2_conv1d_expanddims_1_readvariableop_resource:4
&conv_2_biasadd_readvariableop_resource:H
2conv_3_conv1d_expanddims_1_readvariableop_resource:4
&conv_3_biasadd_readvariableop_resource:H
2conv_4_conv1d_expanddims_1_readvariableop_resource: 4
&conv_4_biasadd_readvariableop_resource: 9
&dense_1_matmul_readvariableop_resource:	?@5
'dense_1_biasadd_readvariableop_resource:@7
%output_matmul_readvariableop_resource:@4
&output_biasadd_readvariableop_resource:
identity??CONV_1/BiasAdd/ReadVariableOp?)CONV_1/conv1d/ExpandDims_1/ReadVariableOp?CONV_2/BiasAdd/ReadVariableOp?)CONV_2/conv1d/ExpandDims_1/ReadVariableOp?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?CONV_3/BiasAdd/ReadVariableOp?)CONV_3/conv1d/ExpandDims_1/ReadVariableOp?CONV_4/BiasAdd/ReadVariableOp?)CONV_4/conv1d/ExpandDims_1/ReadVariableOp?DENSE_1/BiasAdd/ReadVariableOp?DENSE_1/MatMul/ReadVariableOp?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?OUTPUT/BiasAdd/ReadVariableOp?OUTPUT/MatMul/ReadVariableOp?conv1d/BiasAdd/ReadVariableOp?)conv1d/conv1d/ExpandDims_1/ReadVariableOp?,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/conv1d/ExpandDims/dim?
conv1d/conv1d/ExpandDims
ExpandDimsinputs%conv1d/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2
conv1d/conv1d/ExpandDims?
)conv1d/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv1d_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02+
)conv1d/conv1d/ExpandDims_1/ReadVariableOp?
conv1d/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
conv1d/conv1d/ExpandDims_1/dim?
conv1d/conv1d/ExpandDims_1
ExpandDims1conv1d/conv1d/ExpandDims_1/ReadVariableOp:value:0'conv1d/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
conv1d/conv1d/ExpandDims_1?
conv1d/conv1dConv2D!conv1d/conv1d/ExpandDims:output:0#conv1d/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????(*
paddingVALID*
strides
2
conv1d/conv1d?
conv1d/conv1d/SqueezeSqueezeconv1d/conv1d:output:0*
T0*+
_output_shapes
:?????????(*
squeeze_dims

?????????2
conv1d/conv1d/Squeeze?
conv1d/BiasAdd/ReadVariableOpReadVariableOp&conv1d_biasadd_readvariableop_resource*
_output_shapes
:(*
dtype02
conv1d/BiasAdd/ReadVariableOp?
conv1d/BiasAddBiasAddconv1d/conv1d/Squeeze:output:0%conv1d/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????(2
conv1d/BiasAddq
conv1d/ReluReluconv1d/BiasAdd:output:0*
T0*+
_output_shapes
:?????????(2
conv1d/Relu?
CONV_1/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_1/conv1d/ExpandDims/dim?
CONV_1/conv1d/ExpandDims
ExpandDimsconv1d/Relu:activations:0%CONV_1/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????(2
CONV_1/conv1d/ExpandDims?
)CONV_1/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_1_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02+
)CONV_1/conv1d/ExpandDims_1/ReadVariableOp?
CONV_1/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_1/conv1d/ExpandDims_1/dim?
CONV_1/conv1d/ExpandDims_1
ExpandDims1CONV_1/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_1/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
CONV_1/conv1d/ExpandDims_1?
CONV_1/conv1dConv2D!CONV_1/conv1d/ExpandDims:output:0#CONV_1/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????*
paddingSAME*
strides
2
CONV_1/conv1d?
CONV_1/conv1d/SqueezeSqueezeCONV_1/conv1d:output:0*
T0*+
_output_shapes
:?????????*
squeeze_dims

?????????2
CONV_1/conv1d/Squeeze?
CONV_1/BiasAdd/ReadVariableOpReadVariableOp&conv_1_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
CONV_1/BiasAdd/ReadVariableOp?
CONV_1/BiasAddBiasAddCONV_1/conv1d/Squeeze:output:0%CONV_1/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????2
CONV_1/BiasAddq
CONV_1/ReluReluCONV_1/BiasAdd:output:0*
T0*+
_output_shapes
:?????????2
CONV_1/Reluv
POOLING_1/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2
POOLING_1/ExpandDims/dim?
POOLING_1/ExpandDims
ExpandDimsCONV_1/Relu:activations:0!POOLING_1/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2
POOLING_1/ExpandDims?
POOLING_1/MaxPoolMaxPoolPOOLING_1/ExpandDims:output:0*/
_output_shapes
:?????????	*
ksize
*
paddingVALID*
strides
2
POOLING_1/MaxPool?
POOLING_1/SqueezeSqueezePOOLING_1/MaxPool:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims
2
POOLING_1/Squeeze?
CONV_2/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_2/conv1d/ExpandDims/dim?
CONV_2/conv1d/ExpandDims
ExpandDimsPOOLING_1/Squeeze:output:0%CONV_2/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
CONV_2/conv1d/ExpandDims?
)CONV_2/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_2_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02+
)CONV_2/conv1d/ExpandDims_1/ReadVariableOp?
CONV_2/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_2/conv1d/ExpandDims_1/dim?
CONV_2/conv1d/ExpandDims_1
ExpandDims1CONV_2/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_2/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
CONV_2/conv1d/ExpandDims_1?
CONV_2/conv1dConv2D!CONV_2/conv1d/ExpandDims:output:0#CONV_2/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
CONV_2/conv1d?
CONV_2/conv1d/SqueezeSqueezeCONV_2/conv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
CONV_2/conv1d/Squeeze?
CONV_2/BiasAdd/ReadVariableOpReadVariableOp&conv_2_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
CONV_2/BiasAdd/ReadVariableOp?
CONV_2/BiasAddBiasAddCONV_2/conv1d/Squeeze:output:0%CONV_2/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2
CONV_2/BiasAddq
CONV_2/ReluReluCONV_2/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
CONV_2/Relu?
CONV_3/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_3/conv1d/ExpandDims/dim?
CONV_3/conv1d/ExpandDims
ExpandDimsCONV_2/Relu:activations:0%CONV_3/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
CONV_3/conv1d/ExpandDims?
)CONV_3/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_3_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02+
)CONV_3/conv1d/ExpandDims_1/ReadVariableOp?
CONV_3/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_3/conv1d/ExpandDims_1/dim?
CONV_3/conv1d/ExpandDims_1
ExpandDims1CONV_3/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_3/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
CONV_3/conv1d/ExpandDims_1?
CONV_3/conv1dConv2D!CONV_3/conv1d/ExpandDims:output:0#CONV_3/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
CONV_3/conv1d?
CONV_3/conv1d/SqueezeSqueezeCONV_3/conv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
CONV_3/conv1d/Squeeze?
CONV_3/BiasAdd/ReadVariableOpReadVariableOp&conv_3_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
CONV_3/BiasAdd/ReadVariableOp?
CONV_3/BiasAddBiasAddCONV_3/conv1d/Squeeze:output:0%CONV_3/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2
CONV_3/BiasAddq
CONV_3/ReluReluCONV_3/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
CONV_3/Relu?
CONV_4/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_4/conv1d/ExpandDims/dim?
CONV_4/conv1d/ExpandDims
ExpandDimsCONV_3/Relu:activations:0%CONV_4/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
CONV_4/conv1d/ExpandDims?
)CONV_4/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_4_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
: *
dtype02+
)CONV_4/conv1d/ExpandDims_1/ReadVariableOp?
CONV_4/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_4/conv1d/ExpandDims_1/dim?
CONV_4/conv1d/ExpandDims_1
ExpandDims1CONV_4/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_4/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
: 2
CONV_4/conv1d/ExpandDims_1?
CONV_4/conv1dConv2D!CONV_4/conv1d/ExpandDims:output:0#CONV_4/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	 *
paddingSAME*
strides
2
CONV_4/conv1d?
CONV_4/conv1d/SqueezeSqueezeCONV_4/conv1d:output:0*
T0*+
_output_shapes
:?????????	 *
squeeze_dims

?????????2
CONV_4/conv1d/Squeeze?
CONV_4/BiasAdd/ReadVariableOpReadVariableOp&conv_4_biasadd_readvariableop_resource*
_output_shapes
: *
dtype02
CONV_4/BiasAdd/ReadVariableOp?
CONV_4/BiasAddBiasAddCONV_4/conv1d/Squeeze:output:0%CONV_4/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	 2
CONV_4/BiasAddq
CONV_4/ReluReluCONV_4/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	 2
CONV_4/Reluv
POOLING_2/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2
POOLING_2/ExpandDims/dim?
POOLING_2/ExpandDims
ExpandDimsCONV_4/Relu:activations:0!POOLING_2/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	 2
POOLING_2/ExpandDims?
POOLING_2/MaxPoolMaxPoolPOOLING_2/ExpandDims:output:0*/
_output_shapes
:????????? *
ksize
*
paddingVALID*
strides
2
POOLING_2/MaxPool?
POOLING_2/SqueezeSqueezePOOLING_2/MaxPool:output:0*
T0*+
_output_shapes
:????????? *
squeeze_dims
2
POOLING_2/Squeeze?
DROPOUT_1/IdentityIdentityPOOLING_2/Squeeze:output:0*
T0*+
_output_shapes
:????????? 2
DROPOUT_1/Identitye
FC/ConstConst*
_output_shapes
:*
dtype0*
valueB"?????   2

FC/Const?

FC/ReshapeReshapeDROPOUT_1/Identity:output:0FC/Const:output:0*
T0*(
_output_shapes
:??????????2

FC/Reshape?
DENSE_1/MatMul/ReadVariableOpReadVariableOp&dense_1_matmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02
DENSE_1/MatMul/ReadVariableOp?
DENSE_1/MatMulMatMulFC/Reshape:output:0%DENSE_1/MatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
DENSE_1/MatMul?
DENSE_1/BiasAdd/ReadVariableOpReadVariableOp'dense_1_biasadd_readvariableop_resource*
_output_shapes
:@*
dtype02 
DENSE_1/BiasAdd/ReadVariableOp?
DENSE_1/BiasAddBiasAddDENSE_1/MatMul:product:0&DENSE_1/BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
DENSE_1/BiasAddp
DENSE_1/ReluReluDENSE_1/BiasAdd:output:0*
T0*'
_output_shapes
:?????????@2
DENSE_1/Relu?
DROPOUT_2/IdentityIdentityDENSE_1/Relu:activations:0*
T0*'
_output_shapes
:?????????@2
DROPOUT_2/Identity?
OUTPUT/MatMul/ReadVariableOpReadVariableOp%output_matmul_readvariableop_resource*
_output_shapes

:@*
dtype02
OUTPUT/MatMul/ReadVariableOp?
OUTPUT/MatMulMatMulDROPOUT_2/Identity:output:0$OUTPUT/MatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
OUTPUT/MatMul?
OUTPUT/BiasAdd/ReadVariableOpReadVariableOp&output_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
OUTPUT/BiasAdd/ReadVariableOp?
OUTPUT/BiasAddBiasAddOUTPUT/MatMul:product:0%OUTPUT/BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
OUTPUT/BiasAddv
OUTPUT/SoftmaxSoftmaxOUTPUT/BiasAdd:output:0*
T0*'
_output_shapes
:?????????2
OUTPUT/Softmax?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp2conv1d_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp2conv_2_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp&dense_1_matmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentityOUTPUT/Softmax:softmax:0^CONV_1/BiasAdd/ReadVariableOp*^CONV_1/conv1d/ExpandDims_1/ReadVariableOp^CONV_2/BiasAdd/ReadVariableOp*^CONV_2/conv1d/ExpandDims_1/ReadVariableOp-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp^CONV_3/BiasAdd/ReadVariableOp*^CONV_3/conv1d/ExpandDims_1/ReadVariableOp^CONV_4/BiasAdd/ReadVariableOp*^CONV_4/conv1d/ExpandDims_1/ReadVariableOp^DENSE_1/BiasAdd/ReadVariableOp^DENSE_1/MatMul/ReadVariableOp.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp^OUTPUT/BiasAdd/ReadVariableOp^OUTPUT/MatMul/ReadVariableOp^conv1d/BiasAdd/ReadVariableOp*^conv1d/conv1d/ExpandDims_1/ReadVariableOp-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2>
CONV_1/BiasAdd/ReadVariableOpCONV_1/BiasAdd/ReadVariableOp2V
)CONV_1/conv1d/ExpandDims_1/ReadVariableOp)CONV_1/conv1d/ExpandDims_1/ReadVariableOp2>
CONV_2/BiasAdd/ReadVariableOpCONV_2/BiasAdd/ReadVariableOp2V
)CONV_2/conv1d/ExpandDims_1/ReadVariableOp)CONV_2/conv1d/ExpandDims_1/ReadVariableOp2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2>
CONV_3/BiasAdd/ReadVariableOpCONV_3/BiasAdd/ReadVariableOp2V
)CONV_3/conv1d/ExpandDims_1/ReadVariableOp)CONV_3/conv1d/ExpandDims_1/ReadVariableOp2>
CONV_4/BiasAdd/ReadVariableOpCONV_4/BiasAdd/ReadVariableOp2V
)CONV_4/conv1d/ExpandDims_1/ReadVariableOp)CONV_4/conv1d/ExpandDims_1/ReadVariableOp2@
DENSE_1/BiasAdd/ReadVariableOpDENSE_1/BiasAdd/ReadVariableOp2>
DENSE_1/MatMul/ReadVariableOpDENSE_1/MatMul/ReadVariableOp2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2>
OUTPUT/BiasAdd/ReadVariableOpOUTPUT/BiasAdd/ReadVariableOp2<
OUTPUT/MatMul/ReadVariableOpOUTPUT/MatMul/ReadVariableOp2>
conv1d/BiasAdd/ReadVariableOpconv1d/BiasAdd/ReadVariableOp2V
)conv1d/conv1d/ExpandDims_1/ReadVariableOp)conv1d/conv1d/ExpandDims_1/ReadVariableOp2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?
?
'__inference_CONV_4_layer_call_fn_160817

inputs
unknown: 
	unknown_0: 
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	 *$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_4_layer_call_and_return_conditional_losses_1597872
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*+
_output_shapes
:?????????	 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
d
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_159975

inputs
identity?c
dropout/ConstConst*
_output_shapes
: *
dtype0*
valueB
 *   @2
dropout/Constw
dropout/MulMulinputsdropout/Const:output:0*
T0*+
_output_shapes
:????????? 2
dropout/MulT
dropout/ShapeShapeinputs*
T0*
_output_shapes
:2
dropout/Shape?
$dropout/random_uniform/RandomUniformRandomUniformdropout/Shape:output:0*
T0*+
_output_shapes
:????????? *
dtype02&
$dropout/random_uniform/RandomUniformu
dropout/GreaterEqual/yConst*
_output_shapes
: *
dtype0*
valueB
 *   ?2
dropout/GreaterEqual/y?
dropout/GreaterEqualGreaterEqual-dropout/random_uniform/RandomUniform:output:0dropout/GreaterEqual/y:output:0*
T0*+
_output_shapes
:????????? 2
dropout/GreaterEqual?
dropout/CastCastdropout/GreaterEqual:z:0*

DstT0*

SrcT0
*+
_output_shapes
:????????? 2
dropout/Cast~
dropout/Mul_1Muldropout/Mul:z:0dropout/Cast:y:0*
T0*+
_output_shapes
:????????? 2
dropout/Mul_1i
IdentityIdentitydropout/Mul_1:z:0*
T0*+
_output_shapes
:????????? 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
c
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_159837

inputs

identity_1Z
IdentityIdentityinputs*
T0*'
_output_shapes
:?????????@2

Identityi

Identity_1IdentityIdentity:output:0*
T0*'
_output_shapes
:?????????@2

Identity_1"!

identity_1Identity_1:output:0*(
_construction_contextkEagerRuntime*&
_input_shapes
:?????????@:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
a
E__inference_POOLING_2_layer_call_and_return_conditional_losses_159657

inputs
identityb
ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2
ExpandDims/dim?

ExpandDims
ExpandDimsinputsExpandDims/dim:output:0*
T0*A
_output_shapes/
-:+???????????????????????????2

ExpandDims?
MaxPoolMaxPoolExpandDims:output:0*A
_output_shapes/
-:+???????????????????????????*
ksize
*
paddingVALID*
strides
2	
MaxPool?
SqueezeSqueezeMaxPool:output:0*
T0*=
_output_shapes+
):'???????????????????????????*
squeeze_dims
2	
Squeezez
IdentityIdentitySqueeze:output:0*
T0*=
_output_shapes+
):'???????????????????????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*<
_input_shapes+
):'???????????????????????????:e a
=
_output_shapes+
):'???????????????????????????
 
_user_specified_nameinputs
?
Z
>__inference_FC_layer_call_and_return_conditional_losses_159807

inputs
identity_
ConstConst*
_output_shapes
:*
dtype0*
valueB"?????   2
Consth
ReshapeReshapeinputsConst:output:0*
T0*(
_output_shapes
:??????????2	
Reshapee
IdentityIdentityReshape:output:0*
T0*(
_output_shapes
:??????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
F
*__inference_POOLING_1_layer_call_fn_159648

inputs
identity?
PartitionedCallPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *=
_output_shapes+
):'???????????????????????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_1_layer_call_and_return_conditional_losses_1596422
PartitionedCall?
IdentityIdentityPartitionedCall:output:0*
T0*=
_output_shapes+
):'???????????????????????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*<
_input_shapes+
):'???????????????????????????:e a
=
_output_shapes+
):'???????????????????????????
 
_user_specified_nameinputs
?
c
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_160892

inputs

identity_1Z
IdentityIdentityinputs*
T0*'
_output_shapes
:?????????@2

Identityi

Identity_1IdentityIdentity:output:0*
T0*'
_output_shapes
:?????????@2

Identity_1"!

identity_1Identity_1:output:0*(
_construction_contextkEagerRuntime*&
_input_shapes
:?????????@:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
?
B__inference_CONV_1_layer_call_and_return_conditional_losses_160721

inputsA
+conv1d_expanddims_1_readvariableop_resource:(-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????(2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????*
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????2
Relu?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????(: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????(
 
_user_specified_nameinputs
?
?
/__inference_Proposed_Model_layer_call_fn_159906
conv1d_input
unknown:(
	unknown_0:(
	unknown_1:(
	unknown_2:
	unknown_3:
	unknown_4:
	unknown_5:
	unknown_6:
	unknown_7: 
	unknown_8: 
	unknown_9:	?@

unknown_10:@

unknown_11:@

unknown_12:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallconv1d_inputunknown	unknown_0	unknown_1	unknown_2	unknown_3	unknown_4	unknown_5	unknown_6	unknown_7	unknown_8	unknown_9
unknown_10
unknown_11
unknown_12*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*0
_read_only_resource_inputs
	
*-
config_proto

CPU

GPU 2J 8? *S
fNRL
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_1598752
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 22
StatefulPartitionedCallStatefulPartitionedCall:Y U
+
_output_shapes
:?????????
&
_user_specified_nameconv1d_input
?
?
B__inference_CONV_2_layer_call_and_return_conditional_losses_160758

inputsA
+conv1d_expanddims_1_readvariableop_resource:-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
Relu?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????	2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
F
*__inference_DROPOUT_2_layer_call_fn_160909

inputs
identity?
PartitionedCallPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_1598372
PartitionedCalll
IdentityIdentityPartitionedCall:output:0*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*&
_input_shapes
:?????????@:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?

?
B__inference_OUTPUT_layer_call_and_return_conditional_losses_160925

inputs0
matmul_readvariableop_resource:@-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?MatMul/ReadVariableOp?
MatMul/ReadVariableOpReadVariableOpmatmul_readvariableop_resource*
_output_shapes

:@*
dtype02
MatMul/ReadVariableOps
MatMulMatMulinputsMatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
MatMul?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddMatMul:product:0BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2	
BiasAdda
SoftmaxSoftmaxBiasAdd:output:0*
T0*'
_output_shapes
:?????????2	
Softmax?
IdentityIdentitySoftmax:softmax:0^BiasAdd/ReadVariableOp^MatMul/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:?????????@: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2.
MatMul/ReadVariableOpMatMul/ReadVariableOp:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
c
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_160822

inputs

identity_1^
IdentityIdentityinputs*
T0*+
_output_shapes
:????????? 2

Identitym

Identity_1IdentityIdentity:output:0*
T0*+
_output_shapes
:????????? 2

Identity_1"!

identity_1Identity_1:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
d
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_160834

inputs
identity?c
dropout/ConstConst*
_output_shapes
: *
dtype0*
valueB
 *   @2
dropout/Constw
dropout/MulMulinputsdropout/Const:output:0*
T0*+
_output_shapes
:????????? 2
dropout/MulT
dropout/ShapeShapeinputs*
T0*
_output_shapes
:2
dropout/Shape?
$dropout/random_uniform/RandomUniformRandomUniformdropout/Shape:output:0*
T0*+
_output_shapes
:????????? *
dtype02&
$dropout/random_uniform/RandomUniformu
dropout/GreaterEqual/yConst*
_output_shapes
: *
dtype0*
valueB
 *   ?2
dropout/GreaterEqual/y?
dropout/GreaterEqualGreaterEqual-dropout/random_uniform/RandomUniform:output:0dropout/GreaterEqual/y:output:0*
T0*+
_output_shapes
:????????? 2
dropout/GreaterEqual?
dropout/CastCastdropout/GreaterEqual:z:0*

DstT0*

SrcT0
*+
_output_shapes
:????????? 2
dropout/Cast~
dropout/Mul_1Muldropout/Mul:z:0dropout/Cast:y:0*
T0*+
_output_shapes
:????????? 2
dropout/Mul_1i
IdentityIdentitydropout/Mul_1:z:0*
T0*+
_output_shapes
:????????? 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
?
#__inference_FC_layer_call_fn_160855

inputs
identity?
PartitionedCallPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *(
_output_shapes
:??????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *G
fBR@
>__inference_FC_layer_call_and_return_conditional_losses_1598072
PartitionedCallm
IdentityIdentityPartitionedCall:output:0*
T0*(
_output_shapes
:??????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
??
?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160602

inputsH
2conv1d_conv1d_expanddims_1_readvariableop_resource:(4
&conv1d_biasadd_readvariableop_resource:(H
2conv_1_conv1d_expanddims_1_readvariableop_resource:(4
&conv_1_biasadd_readvariableop_resource:H
2conv_2_conv1d_expanddims_1_readvariableop_resource:4
&conv_2_biasadd_readvariableop_resource:H
2conv_3_conv1d_expanddims_1_readvariableop_resource:4
&conv_3_biasadd_readvariableop_resource:H
2conv_4_conv1d_expanddims_1_readvariableop_resource: 4
&conv_4_biasadd_readvariableop_resource: 9
&dense_1_matmul_readvariableop_resource:	?@5
'dense_1_biasadd_readvariableop_resource:@7
%output_matmul_readvariableop_resource:@4
&output_biasadd_readvariableop_resource:
identity??CONV_1/BiasAdd/ReadVariableOp?)CONV_1/conv1d/ExpandDims_1/ReadVariableOp?CONV_2/BiasAdd/ReadVariableOp?)CONV_2/conv1d/ExpandDims_1/ReadVariableOp?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?CONV_3/BiasAdd/ReadVariableOp?)CONV_3/conv1d/ExpandDims_1/ReadVariableOp?CONV_4/BiasAdd/ReadVariableOp?)CONV_4/conv1d/ExpandDims_1/ReadVariableOp?DENSE_1/BiasAdd/ReadVariableOp?DENSE_1/MatMul/ReadVariableOp?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?OUTPUT/BiasAdd/ReadVariableOp?OUTPUT/MatMul/ReadVariableOp?conv1d/BiasAdd/ReadVariableOp?)conv1d/conv1d/ExpandDims_1/ReadVariableOp?,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/conv1d/ExpandDims/dim?
conv1d/conv1d/ExpandDims
ExpandDimsinputs%conv1d/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2
conv1d/conv1d/ExpandDims?
)conv1d/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv1d_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02+
)conv1d/conv1d/ExpandDims_1/ReadVariableOp?
conv1d/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
conv1d/conv1d/ExpandDims_1/dim?
conv1d/conv1d/ExpandDims_1
ExpandDims1conv1d/conv1d/ExpandDims_1/ReadVariableOp:value:0'conv1d/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
conv1d/conv1d/ExpandDims_1?
conv1d/conv1dConv2D!conv1d/conv1d/ExpandDims:output:0#conv1d/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????(*
paddingVALID*
strides
2
conv1d/conv1d?
conv1d/conv1d/SqueezeSqueezeconv1d/conv1d:output:0*
T0*+
_output_shapes
:?????????(*
squeeze_dims

?????????2
conv1d/conv1d/Squeeze?
conv1d/BiasAdd/ReadVariableOpReadVariableOp&conv1d_biasadd_readvariableop_resource*
_output_shapes
:(*
dtype02
conv1d/BiasAdd/ReadVariableOp?
conv1d/BiasAddBiasAddconv1d/conv1d/Squeeze:output:0%conv1d/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????(2
conv1d/BiasAddq
conv1d/ReluReluconv1d/BiasAdd:output:0*
T0*+
_output_shapes
:?????????(2
conv1d/Relu?
CONV_1/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_1/conv1d/ExpandDims/dim?
CONV_1/conv1d/ExpandDims
ExpandDimsconv1d/Relu:activations:0%CONV_1/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????(2
CONV_1/conv1d/ExpandDims?
)CONV_1/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_1_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02+
)CONV_1/conv1d/ExpandDims_1/ReadVariableOp?
CONV_1/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_1/conv1d/ExpandDims_1/dim?
CONV_1/conv1d/ExpandDims_1
ExpandDims1CONV_1/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_1/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
CONV_1/conv1d/ExpandDims_1?
CONV_1/conv1dConv2D!CONV_1/conv1d/ExpandDims:output:0#CONV_1/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????*
paddingSAME*
strides
2
CONV_1/conv1d?
CONV_1/conv1d/SqueezeSqueezeCONV_1/conv1d:output:0*
T0*+
_output_shapes
:?????????*
squeeze_dims

?????????2
CONV_1/conv1d/Squeeze?
CONV_1/BiasAdd/ReadVariableOpReadVariableOp&conv_1_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
CONV_1/BiasAdd/ReadVariableOp?
CONV_1/BiasAddBiasAddCONV_1/conv1d/Squeeze:output:0%CONV_1/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????2
CONV_1/BiasAddq
CONV_1/ReluReluCONV_1/BiasAdd:output:0*
T0*+
_output_shapes
:?????????2
CONV_1/Reluv
POOLING_1/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2
POOLING_1/ExpandDims/dim?
POOLING_1/ExpandDims
ExpandDimsCONV_1/Relu:activations:0!POOLING_1/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2
POOLING_1/ExpandDims?
POOLING_1/MaxPoolMaxPoolPOOLING_1/ExpandDims:output:0*/
_output_shapes
:?????????	*
ksize
*
paddingVALID*
strides
2
POOLING_1/MaxPool?
POOLING_1/SqueezeSqueezePOOLING_1/MaxPool:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims
2
POOLING_1/Squeeze?
CONV_2/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_2/conv1d/ExpandDims/dim?
CONV_2/conv1d/ExpandDims
ExpandDimsPOOLING_1/Squeeze:output:0%CONV_2/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
CONV_2/conv1d/ExpandDims?
)CONV_2/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_2_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02+
)CONV_2/conv1d/ExpandDims_1/ReadVariableOp?
CONV_2/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_2/conv1d/ExpandDims_1/dim?
CONV_2/conv1d/ExpandDims_1
ExpandDims1CONV_2/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_2/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
CONV_2/conv1d/ExpandDims_1?
CONV_2/conv1dConv2D!CONV_2/conv1d/ExpandDims:output:0#CONV_2/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
CONV_2/conv1d?
CONV_2/conv1d/SqueezeSqueezeCONV_2/conv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
CONV_2/conv1d/Squeeze?
CONV_2/BiasAdd/ReadVariableOpReadVariableOp&conv_2_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
CONV_2/BiasAdd/ReadVariableOp?
CONV_2/BiasAddBiasAddCONV_2/conv1d/Squeeze:output:0%CONV_2/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2
CONV_2/BiasAddq
CONV_2/ReluReluCONV_2/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
CONV_2/Relu?
CONV_3/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_3/conv1d/ExpandDims/dim?
CONV_3/conv1d/ExpandDims
ExpandDimsCONV_2/Relu:activations:0%CONV_3/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
CONV_3/conv1d/ExpandDims?
)CONV_3/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_3_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02+
)CONV_3/conv1d/ExpandDims_1/ReadVariableOp?
CONV_3/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_3/conv1d/ExpandDims_1/dim?
CONV_3/conv1d/ExpandDims_1
ExpandDims1CONV_3/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_3/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
CONV_3/conv1d/ExpandDims_1?
CONV_3/conv1dConv2D!CONV_3/conv1d/ExpandDims:output:0#CONV_3/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
CONV_3/conv1d?
CONV_3/conv1d/SqueezeSqueezeCONV_3/conv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
CONV_3/conv1d/Squeeze?
CONV_3/BiasAdd/ReadVariableOpReadVariableOp&conv_3_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
CONV_3/BiasAdd/ReadVariableOp?
CONV_3/BiasAddBiasAddCONV_3/conv1d/Squeeze:output:0%CONV_3/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2
CONV_3/BiasAddq
CONV_3/ReluReluCONV_3/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
CONV_3/Relu?
CONV_4/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
CONV_4/conv1d/ExpandDims/dim?
CONV_4/conv1d/ExpandDims
ExpandDimsCONV_3/Relu:activations:0%CONV_4/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
CONV_4/conv1d/ExpandDims?
)CONV_4/conv1d/ExpandDims_1/ReadVariableOpReadVariableOp2conv_4_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
: *
dtype02+
)CONV_4/conv1d/ExpandDims_1/ReadVariableOp?
CONV_4/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2 
CONV_4/conv1d/ExpandDims_1/dim?
CONV_4/conv1d/ExpandDims_1
ExpandDims1CONV_4/conv1d/ExpandDims_1/ReadVariableOp:value:0'CONV_4/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
: 2
CONV_4/conv1d/ExpandDims_1?
CONV_4/conv1dConv2D!CONV_4/conv1d/ExpandDims:output:0#CONV_4/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	 *
paddingSAME*
strides
2
CONV_4/conv1d?
CONV_4/conv1d/SqueezeSqueezeCONV_4/conv1d:output:0*
T0*+
_output_shapes
:?????????	 *
squeeze_dims

?????????2
CONV_4/conv1d/Squeeze?
CONV_4/BiasAdd/ReadVariableOpReadVariableOp&conv_4_biasadd_readvariableop_resource*
_output_shapes
: *
dtype02
CONV_4/BiasAdd/ReadVariableOp?
CONV_4/BiasAddBiasAddCONV_4/conv1d/Squeeze:output:0%CONV_4/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	 2
CONV_4/BiasAddq
CONV_4/ReluReluCONV_4/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	 2
CONV_4/Reluv
POOLING_2/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2
POOLING_2/ExpandDims/dim?
POOLING_2/ExpandDims
ExpandDimsCONV_4/Relu:activations:0!POOLING_2/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	 2
POOLING_2/ExpandDims?
POOLING_2/MaxPoolMaxPoolPOOLING_2/ExpandDims:output:0*/
_output_shapes
:????????? *
ksize
*
paddingVALID*
strides
2
POOLING_2/MaxPool?
POOLING_2/SqueezeSqueezePOOLING_2/MaxPool:output:0*
T0*+
_output_shapes
:????????? *
squeeze_dims
2
POOLING_2/Squeezew
DROPOUT_1/dropout/ConstConst*
_output_shapes
: *
dtype0*
valueB
 *   @2
DROPOUT_1/dropout/Const?
DROPOUT_1/dropout/MulMulPOOLING_2/Squeeze:output:0 DROPOUT_1/dropout/Const:output:0*
T0*+
_output_shapes
:????????? 2
DROPOUT_1/dropout/Mul|
DROPOUT_1/dropout/ShapeShapePOOLING_2/Squeeze:output:0*
T0*
_output_shapes
:2
DROPOUT_1/dropout/Shape?
.DROPOUT_1/dropout/random_uniform/RandomUniformRandomUniform DROPOUT_1/dropout/Shape:output:0*
T0*+
_output_shapes
:????????? *
dtype020
.DROPOUT_1/dropout/random_uniform/RandomUniform?
 DROPOUT_1/dropout/GreaterEqual/yConst*
_output_shapes
: *
dtype0*
valueB
 *   ?2"
 DROPOUT_1/dropout/GreaterEqual/y?
DROPOUT_1/dropout/GreaterEqualGreaterEqual7DROPOUT_1/dropout/random_uniform/RandomUniform:output:0)DROPOUT_1/dropout/GreaterEqual/y:output:0*
T0*+
_output_shapes
:????????? 2 
DROPOUT_1/dropout/GreaterEqual?
DROPOUT_1/dropout/CastCast"DROPOUT_1/dropout/GreaterEqual:z:0*

DstT0*

SrcT0
*+
_output_shapes
:????????? 2
DROPOUT_1/dropout/Cast?
DROPOUT_1/dropout/Mul_1MulDROPOUT_1/dropout/Mul:z:0DROPOUT_1/dropout/Cast:y:0*
T0*+
_output_shapes
:????????? 2
DROPOUT_1/dropout/Mul_1e
FC/ConstConst*
_output_shapes
:*
dtype0*
valueB"?????   2

FC/Const?

FC/ReshapeReshapeDROPOUT_1/dropout/Mul_1:z:0FC/Const:output:0*
T0*(
_output_shapes
:??????????2

FC/Reshape?
DENSE_1/MatMul/ReadVariableOpReadVariableOp&dense_1_matmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02
DENSE_1/MatMul/ReadVariableOp?
DENSE_1/MatMulMatMulFC/Reshape:output:0%DENSE_1/MatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
DENSE_1/MatMul?
DENSE_1/BiasAdd/ReadVariableOpReadVariableOp'dense_1_biasadd_readvariableop_resource*
_output_shapes
:@*
dtype02 
DENSE_1/BiasAdd/ReadVariableOp?
DENSE_1/BiasAddBiasAddDENSE_1/MatMul:product:0&DENSE_1/BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
DENSE_1/BiasAddp
DENSE_1/ReluReluDENSE_1/BiasAdd:output:0*
T0*'
_output_shapes
:?????????@2
DENSE_1/Reluw
DROPOUT_2/dropout/ConstConst*
_output_shapes
: *
dtype0*
valueB
 *   @2
DROPOUT_2/dropout/Const?
DROPOUT_2/dropout/MulMulDENSE_1/Relu:activations:0 DROPOUT_2/dropout/Const:output:0*
T0*'
_output_shapes
:?????????@2
DROPOUT_2/dropout/Mul|
DROPOUT_2/dropout/ShapeShapeDENSE_1/Relu:activations:0*
T0*
_output_shapes
:2
DROPOUT_2/dropout/Shape?
.DROPOUT_2/dropout/random_uniform/RandomUniformRandomUniform DROPOUT_2/dropout/Shape:output:0*
T0*'
_output_shapes
:?????????@*
dtype020
.DROPOUT_2/dropout/random_uniform/RandomUniform?
 DROPOUT_2/dropout/GreaterEqual/yConst*
_output_shapes
: *
dtype0*
valueB
 *   ?2"
 DROPOUT_2/dropout/GreaterEqual/y?
DROPOUT_2/dropout/GreaterEqualGreaterEqual7DROPOUT_2/dropout/random_uniform/RandomUniform:output:0)DROPOUT_2/dropout/GreaterEqual/y:output:0*
T0*'
_output_shapes
:?????????@2 
DROPOUT_2/dropout/GreaterEqual?
DROPOUT_2/dropout/CastCast"DROPOUT_2/dropout/GreaterEqual:z:0*

DstT0*

SrcT0
*'
_output_shapes
:?????????@2
DROPOUT_2/dropout/Cast?
DROPOUT_2/dropout/Mul_1MulDROPOUT_2/dropout/Mul:z:0DROPOUT_2/dropout/Cast:y:0*
T0*'
_output_shapes
:?????????@2
DROPOUT_2/dropout/Mul_1?
OUTPUT/MatMul/ReadVariableOpReadVariableOp%output_matmul_readvariableop_resource*
_output_shapes

:@*
dtype02
OUTPUT/MatMul/ReadVariableOp?
OUTPUT/MatMulMatMulDROPOUT_2/dropout/Mul_1:z:0$OUTPUT/MatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
OUTPUT/MatMul?
OUTPUT/BiasAdd/ReadVariableOpReadVariableOp&output_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02
OUTPUT/BiasAdd/ReadVariableOp?
OUTPUT/BiasAddBiasAddOUTPUT/MatMul:product:0%OUTPUT/BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
OUTPUT/BiasAddv
OUTPUT/SoftmaxSoftmaxOUTPUT/BiasAdd:output:0*
T0*'
_output_shapes
:?????????2
OUTPUT/Softmax?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp2conv1d_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp2conv_2_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp&dense_1_matmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentityOUTPUT/Softmax:softmax:0^CONV_1/BiasAdd/ReadVariableOp*^CONV_1/conv1d/ExpandDims_1/ReadVariableOp^CONV_2/BiasAdd/ReadVariableOp*^CONV_2/conv1d/ExpandDims_1/ReadVariableOp-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp^CONV_3/BiasAdd/ReadVariableOp*^CONV_3/conv1d/ExpandDims_1/ReadVariableOp^CONV_4/BiasAdd/ReadVariableOp*^CONV_4/conv1d/ExpandDims_1/ReadVariableOp^DENSE_1/BiasAdd/ReadVariableOp^DENSE_1/MatMul/ReadVariableOp.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp^OUTPUT/BiasAdd/ReadVariableOp^OUTPUT/MatMul/ReadVariableOp^conv1d/BiasAdd/ReadVariableOp*^conv1d/conv1d/ExpandDims_1/ReadVariableOp-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2>
CONV_1/BiasAdd/ReadVariableOpCONV_1/BiasAdd/ReadVariableOp2V
)CONV_1/conv1d/ExpandDims_1/ReadVariableOp)CONV_1/conv1d/ExpandDims_1/ReadVariableOp2>
CONV_2/BiasAdd/ReadVariableOpCONV_2/BiasAdd/ReadVariableOp2V
)CONV_2/conv1d/ExpandDims_1/ReadVariableOp)CONV_2/conv1d/ExpandDims_1/ReadVariableOp2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2>
CONV_3/BiasAdd/ReadVariableOpCONV_3/BiasAdd/ReadVariableOp2V
)CONV_3/conv1d/ExpandDims_1/ReadVariableOp)CONV_3/conv1d/ExpandDims_1/ReadVariableOp2>
CONV_4/BiasAdd/ReadVariableOpCONV_4/BiasAdd/ReadVariableOp2V
)CONV_4/conv1d/ExpandDims_1/ReadVariableOp)CONV_4/conv1d/ExpandDims_1/ReadVariableOp2@
DENSE_1/BiasAdd/ReadVariableOpDENSE_1/BiasAdd/ReadVariableOp2>
DENSE_1/MatMul/ReadVariableOpDENSE_1/MatMul/ReadVariableOp2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2>
OUTPUT/BiasAdd/ReadVariableOpOUTPUT/BiasAdd/ReadVariableOp2<
OUTPUT/MatMul/ReadVariableOpOUTPUT/MatMul/ReadVariableOp2>
conv1d/BiasAdd/ReadVariableOpconv1d/BiasAdd/ReadVariableOp2V
)conv1d/conv1d/ExpandDims_1/ReadVariableOp)conv1d/conv1d/ExpandDims_1/ReadVariableOp2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?P
?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_159875

inputs#
conv1d_159693:(
conv1d_159695:(#
conv_1_159715:(
conv_1_159717:#
conv_2_159744:
conv_2_159746:#
conv_3_159766:
conv_3_159768:#
conv_4_159788: 
conv_4_159790: !
dense_1_159827:	?@
dense_1_159829:@
output_159851:@
output_159853:
identity??CONV_1/StatefulPartitionedCall?CONV_2/StatefulPartitionedCall?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?CONV_3/StatefulPartitionedCall?CONV_4/StatefulPartitionedCall?DENSE_1/StatefulPartitionedCall?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?OUTPUT/StatefulPartitionedCall?conv1d/StatefulPartitionedCall?,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/StatefulPartitionedCallStatefulPartitionedCallinputsconv1d_159693conv1d_159695*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????(*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_conv1d_layer_call_and_return_conditional_losses_1596922 
conv1d/StatefulPartitionedCall?
CONV_1/StatefulPartitionedCallStatefulPartitionedCall'conv1d/StatefulPartitionedCall:output:0conv_1_159715conv_1_159717*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_1_layer_call_and_return_conditional_losses_1597142 
CONV_1/StatefulPartitionedCall?
POOLING_1/PartitionedCallPartitionedCall'CONV_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_1_layer_call_and_return_conditional_losses_1596422
POOLING_1/PartitionedCall?
CONV_2/StatefulPartitionedCallStatefulPartitionedCall"POOLING_1/PartitionedCall:output:0conv_2_159744conv_2_159746*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_2_layer_call_and_return_conditional_losses_1597432 
CONV_2/StatefulPartitionedCall?
CONV_3/StatefulPartitionedCallStatefulPartitionedCall'CONV_2/StatefulPartitionedCall:output:0conv_3_159766conv_3_159768*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_3_layer_call_and_return_conditional_losses_1597652 
CONV_3/StatefulPartitionedCall?
CONV_4/StatefulPartitionedCallStatefulPartitionedCall'CONV_3/StatefulPartitionedCall:output:0conv_4_159788conv_4_159790*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	 *$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_4_layer_call_and_return_conditional_losses_1597872 
CONV_4/StatefulPartitionedCall?
POOLING_2/PartitionedCallPartitionedCall'CONV_4/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_2_layer_call_and_return_conditional_losses_1596572
POOLING_2/PartitionedCall?
DROPOUT_1/PartitionedCallPartitionedCall"POOLING_2/PartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_1597992
DROPOUT_1/PartitionedCall?
FC/PartitionedCallPartitionedCall"DROPOUT_1/PartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *(
_output_shapes
:??????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *G
fBR@
>__inference_FC_layer_call_and_return_conditional_losses_1598072
FC/PartitionedCall?
DENSE_1/StatefulPartitionedCallStatefulPartitionedCallFC/PartitionedCall:output:0dense_1_159827dense_1_159829*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *L
fGRE
C__inference_DENSE_1_layer_call_and_return_conditional_losses_1598262!
DENSE_1/StatefulPartitionedCall?
DROPOUT_2/PartitionedCallPartitionedCall(DENSE_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_1598372
DROPOUT_2/PartitionedCall?
OUTPUT/StatefulPartitionedCallStatefulPartitionedCall"DROPOUT_2/PartitionedCall:output:0output_159851output_159853*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_OUTPUT_layer_call_and_return_conditional_losses_1598502 
OUTPUT/StatefulPartitionedCall?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv1d_159693*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv_2_159744*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpdense_1_159827*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentity'OUTPUT/StatefulPartitionedCall:output:0^CONV_1/StatefulPartitionedCall^CONV_2/StatefulPartitionedCall-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp^CONV_3/StatefulPartitionedCall^CONV_4/StatefulPartitionedCall ^DENSE_1/StatefulPartitionedCall.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp^OUTPUT/StatefulPartitionedCall^conv1d/StatefulPartitionedCall-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2@
CONV_1/StatefulPartitionedCallCONV_1/StatefulPartitionedCall2@
CONV_2/StatefulPartitionedCallCONV_2/StatefulPartitionedCall2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2@
CONV_3/StatefulPartitionedCallCONV_3/StatefulPartitionedCall2@
CONV_4/StatefulPartitionedCallCONV_4/StatefulPartitionedCall2B
DENSE_1/StatefulPartitionedCallDENSE_1/StatefulPartitionedCall2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2@
OUTPUT/StatefulPartitionedCallOUTPUT/StatefulPartitionedCall2@
conv1d/StatefulPartitionedCallconv1d/StatefulPartitionedCall2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
??
?
"__inference__traced_restore_161306
file_prefix4
assignvariableop_conv1d_kernel:(,
assignvariableop_1_conv1d_bias:(6
 assignvariableop_2_conv_1_kernel:(,
assignvariableop_3_conv_1_bias:6
 assignvariableop_4_conv_2_kernel:,
assignvariableop_5_conv_2_bias:6
 assignvariableop_6_conv_3_kernel:,
assignvariableop_7_conv_3_bias:6
 assignvariableop_8_conv_4_kernel: ,
assignvariableop_9_conv_4_bias: 5
"assignvariableop_10_dense_1_kernel:	?@.
 assignvariableop_11_dense_1_bias:@3
!assignvariableop_12_output_kernel:@-
assignvariableop_13_output_bias:'
assignvariableop_14_adam_iter:	 )
assignvariableop_15_adam_beta_1: )
assignvariableop_16_adam_beta_2: (
assignvariableop_17_adam_decay: 0
&assignvariableop_18_adam_learning_rate: #
assignvariableop_19_total: #
assignvariableop_20_count: %
assignvariableop_21_total_1: %
assignvariableop_22_count_1: >
(assignvariableop_23_adam_conv1d_kernel_m:(4
&assignvariableop_24_adam_conv1d_bias_m:(>
(assignvariableop_25_adam_conv_1_kernel_m:(4
&assignvariableop_26_adam_conv_1_bias_m:>
(assignvariableop_27_adam_conv_2_kernel_m:4
&assignvariableop_28_adam_conv_2_bias_m:>
(assignvariableop_29_adam_conv_3_kernel_m:4
&assignvariableop_30_adam_conv_3_bias_m:>
(assignvariableop_31_adam_conv_4_kernel_m: 4
&assignvariableop_32_adam_conv_4_bias_m: <
)assignvariableop_33_adam_dense_1_kernel_m:	?@5
'assignvariableop_34_adam_dense_1_bias_m:@:
(assignvariableop_35_adam_output_kernel_m:@4
&assignvariableop_36_adam_output_bias_m:>
(assignvariableop_37_adam_conv1d_kernel_v:(4
&assignvariableop_38_adam_conv1d_bias_v:(>
(assignvariableop_39_adam_conv_1_kernel_v:(4
&assignvariableop_40_adam_conv_1_bias_v:>
(assignvariableop_41_adam_conv_2_kernel_v:4
&assignvariableop_42_adam_conv_2_bias_v:>
(assignvariableop_43_adam_conv_3_kernel_v:4
&assignvariableop_44_adam_conv_3_bias_v:>
(assignvariableop_45_adam_conv_4_kernel_v: 4
&assignvariableop_46_adam_conv_4_bias_v: <
)assignvariableop_47_adam_dense_1_kernel_v:	?@5
'assignvariableop_48_adam_dense_1_bias_v:@:
(assignvariableop_49_adam_output_kernel_v:@4
&assignvariableop_50_adam_output_bias_v:
identity_52??AssignVariableOp?AssignVariableOp_1?AssignVariableOp_10?AssignVariableOp_11?AssignVariableOp_12?AssignVariableOp_13?AssignVariableOp_14?AssignVariableOp_15?AssignVariableOp_16?AssignVariableOp_17?AssignVariableOp_18?AssignVariableOp_19?AssignVariableOp_2?AssignVariableOp_20?AssignVariableOp_21?AssignVariableOp_22?AssignVariableOp_23?AssignVariableOp_24?AssignVariableOp_25?AssignVariableOp_26?AssignVariableOp_27?AssignVariableOp_28?AssignVariableOp_29?AssignVariableOp_3?AssignVariableOp_30?AssignVariableOp_31?AssignVariableOp_32?AssignVariableOp_33?AssignVariableOp_34?AssignVariableOp_35?AssignVariableOp_36?AssignVariableOp_37?AssignVariableOp_38?AssignVariableOp_39?AssignVariableOp_4?AssignVariableOp_40?AssignVariableOp_41?AssignVariableOp_42?AssignVariableOp_43?AssignVariableOp_44?AssignVariableOp_45?AssignVariableOp_46?AssignVariableOp_47?AssignVariableOp_48?AssignVariableOp_49?AssignVariableOp_5?AssignVariableOp_50?AssignVariableOp_6?AssignVariableOp_7?AssignVariableOp_8?AssignVariableOp_9?
RestoreV2/tensor_namesConst"/device:CPU:0*
_output_shapes
:4*
dtype0*?
value?B?4B6layer_with_weights-0/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-0/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-1/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-1/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-2/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-2/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-3/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-3/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-4/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-4/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-5/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-5/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-6/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-6/bias/.ATTRIBUTES/VARIABLE_VALUEB)optimizer/iter/.ATTRIBUTES/VARIABLE_VALUEB+optimizer/beta_1/.ATTRIBUTES/VARIABLE_VALUEB+optimizer/beta_2/.ATTRIBUTES/VARIABLE_VALUEB*optimizer/decay/.ATTRIBUTES/VARIABLE_VALUEB2optimizer/learning_rate/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/0/total/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/0/count/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/1/total/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/1/count/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-0/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-0/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-1/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-1/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-2/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-2/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-3/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-3/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-4/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-4/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-5/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-5/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-6/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-6/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-0/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-0/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-1/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-1/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-2/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-2/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-3/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-3/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-4/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-4/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-5/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-5/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-6/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-6/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEB_CHECKPOINTABLE_OBJECT_GRAPH2
RestoreV2/tensor_names?
RestoreV2/shape_and_slicesConst"/device:CPU:0*
_output_shapes
:4*
dtype0*{
valuerBp4B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B 2
RestoreV2/shape_and_slices?
	RestoreV2	RestoreV2file_prefixRestoreV2/tensor_names:output:0#RestoreV2/shape_and_slices:output:0"/device:CPU:0*?
_output_shapes?
?::::::::::::::::::::::::::::::::::::::::::::::::::::*B
dtypes8
624	2
	RestoreV2g
IdentityIdentityRestoreV2:tensors:0"/device:CPU:0*
T0*
_output_shapes
:2

Identity?
AssignVariableOpAssignVariableOpassignvariableop_conv1d_kernelIdentity:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOpk

Identity_1IdentityRestoreV2:tensors:1"/device:CPU:0*
T0*
_output_shapes
:2

Identity_1?
AssignVariableOp_1AssignVariableOpassignvariableop_1_conv1d_biasIdentity_1:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_1k

Identity_2IdentityRestoreV2:tensors:2"/device:CPU:0*
T0*
_output_shapes
:2

Identity_2?
AssignVariableOp_2AssignVariableOp assignvariableop_2_conv_1_kernelIdentity_2:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_2k

Identity_3IdentityRestoreV2:tensors:3"/device:CPU:0*
T0*
_output_shapes
:2

Identity_3?
AssignVariableOp_3AssignVariableOpassignvariableop_3_conv_1_biasIdentity_3:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_3k

Identity_4IdentityRestoreV2:tensors:4"/device:CPU:0*
T0*
_output_shapes
:2

Identity_4?
AssignVariableOp_4AssignVariableOp assignvariableop_4_conv_2_kernelIdentity_4:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_4k

Identity_5IdentityRestoreV2:tensors:5"/device:CPU:0*
T0*
_output_shapes
:2

Identity_5?
AssignVariableOp_5AssignVariableOpassignvariableop_5_conv_2_biasIdentity_5:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_5k

Identity_6IdentityRestoreV2:tensors:6"/device:CPU:0*
T0*
_output_shapes
:2

Identity_6?
AssignVariableOp_6AssignVariableOp assignvariableop_6_conv_3_kernelIdentity_6:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_6k

Identity_7IdentityRestoreV2:tensors:7"/device:CPU:0*
T0*
_output_shapes
:2

Identity_7?
AssignVariableOp_7AssignVariableOpassignvariableop_7_conv_3_biasIdentity_7:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_7k

Identity_8IdentityRestoreV2:tensors:8"/device:CPU:0*
T0*
_output_shapes
:2

Identity_8?
AssignVariableOp_8AssignVariableOp assignvariableop_8_conv_4_kernelIdentity_8:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_8k

Identity_9IdentityRestoreV2:tensors:9"/device:CPU:0*
T0*
_output_shapes
:2

Identity_9?
AssignVariableOp_9AssignVariableOpassignvariableop_9_conv_4_biasIdentity_9:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_9n
Identity_10IdentityRestoreV2:tensors:10"/device:CPU:0*
T0*
_output_shapes
:2
Identity_10?
AssignVariableOp_10AssignVariableOp"assignvariableop_10_dense_1_kernelIdentity_10:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_10n
Identity_11IdentityRestoreV2:tensors:11"/device:CPU:0*
T0*
_output_shapes
:2
Identity_11?
AssignVariableOp_11AssignVariableOp assignvariableop_11_dense_1_biasIdentity_11:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_11n
Identity_12IdentityRestoreV2:tensors:12"/device:CPU:0*
T0*
_output_shapes
:2
Identity_12?
AssignVariableOp_12AssignVariableOp!assignvariableop_12_output_kernelIdentity_12:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_12n
Identity_13IdentityRestoreV2:tensors:13"/device:CPU:0*
T0*
_output_shapes
:2
Identity_13?
AssignVariableOp_13AssignVariableOpassignvariableop_13_output_biasIdentity_13:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_13n
Identity_14IdentityRestoreV2:tensors:14"/device:CPU:0*
T0	*
_output_shapes
:2
Identity_14?
AssignVariableOp_14AssignVariableOpassignvariableop_14_adam_iterIdentity_14:output:0"/device:CPU:0*
_output_shapes
 *
dtype0	2
AssignVariableOp_14n
Identity_15IdentityRestoreV2:tensors:15"/device:CPU:0*
T0*
_output_shapes
:2
Identity_15?
AssignVariableOp_15AssignVariableOpassignvariableop_15_adam_beta_1Identity_15:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_15n
Identity_16IdentityRestoreV2:tensors:16"/device:CPU:0*
T0*
_output_shapes
:2
Identity_16?
AssignVariableOp_16AssignVariableOpassignvariableop_16_adam_beta_2Identity_16:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_16n
Identity_17IdentityRestoreV2:tensors:17"/device:CPU:0*
T0*
_output_shapes
:2
Identity_17?
AssignVariableOp_17AssignVariableOpassignvariableop_17_adam_decayIdentity_17:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_17n
Identity_18IdentityRestoreV2:tensors:18"/device:CPU:0*
T0*
_output_shapes
:2
Identity_18?
AssignVariableOp_18AssignVariableOp&assignvariableop_18_adam_learning_rateIdentity_18:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_18n
Identity_19IdentityRestoreV2:tensors:19"/device:CPU:0*
T0*
_output_shapes
:2
Identity_19?
AssignVariableOp_19AssignVariableOpassignvariableop_19_totalIdentity_19:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_19n
Identity_20IdentityRestoreV2:tensors:20"/device:CPU:0*
T0*
_output_shapes
:2
Identity_20?
AssignVariableOp_20AssignVariableOpassignvariableop_20_countIdentity_20:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_20n
Identity_21IdentityRestoreV2:tensors:21"/device:CPU:0*
T0*
_output_shapes
:2
Identity_21?
AssignVariableOp_21AssignVariableOpassignvariableop_21_total_1Identity_21:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_21n
Identity_22IdentityRestoreV2:tensors:22"/device:CPU:0*
T0*
_output_shapes
:2
Identity_22?
AssignVariableOp_22AssignVariableOpassignvariableop_22_count_1Identity_22:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_22n
Identity_23IdentityRestoreV2:tensors:23"/device:CPU:0*
T0*
_output_shapes
:2
Identity_23?
AssignVariableOp_23AssignVariableOp(assignvariableop_23_adam_conv1d_kernel_mIdentity_23:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_23n
Identity_24IdentityRestoreV2:tensors:24"/device:CPU:0*
T0*
_output_shapes
:2
Identity_24?
AssignVariableOp_24AssignVariableOp&assignvariableop_24_adam_conv1d_bias_mIdentity_24:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_24n
Identity_25IdentityRestoreV2:tensors:25"/device:CPU:0*
T0*
_output_shapes
:2
Identity_25?
AssignVariableOp_25AssignVariableOp(assignvariableop_25_adam_conv_1_kernel_mIdentity_25:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_25n
Identity_26IdentityRestoreV2:tensors:26"/device:CPU:0*
T0*
_output_shapes
:2
Identity_26?
AssignVariableOp_26AssignVariableOp&assignvariableop_26_adam_conv_1_bias_mIdentity_26:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_26n
Identity_27IdentityRestoreV2:tensors:27"/device:CPU:0*
T0*
_output_shapes
:2
Identity_27?
AssignVariableOp_27AssignVariableOp(assignvariableop_27_adam_conv_2_kernel_mIdentity_27:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_27n
Identity_28IdentityRestoreV2:tensors:28"/device:CPU:0*
T0*
_output_shapes
:2
Identity_28?
AssignVariableOp_28AssignVariableOp&assignvariableop_28_adam_conv_2_bias_mIdentity_28:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_28n
Identity_29IdentityRestoreV2:tensors:29"/device:CPU:0*
T0*
_output_shapes
:2
Identity_29?
AssignVariableOp_29AssignVariableOp(assignvariableop_29_adam_conv_3_kernel_mIdentity_29:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_29n
Identity_30IdentityRestoreV2:tensors:30"/device:CPU:0*
T0*
_output_shapes
:2
Identity_30?
AssignVariableOp_30AssignVariableOp&assignvariableop_30_adam_conv_3_bias_mIdentity_30:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_30n
Identity_31IdentityRestoreV2:tensors:31"/device:CPU:0*
T0*
_output_shapes
:2
Identity_31?
AssignVariableOp_31AssignVariableOp(assignvariableop_31_adam_conv_4_kernel_mIdentity_31:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_31n
Identity_32IdentityRestoreV2:tensors:32"/device:CPU:0*
T0*
_output_shapes
:2
Identity_32?
AssignVariableOp_32AssignVariableOp&assignvariableop_32_adam_conv_4_bias_mIdentity_32:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_32n
Identity_33IdentityRestoreV2:tensors:33"/device:CPU:0*
T0*
_output_shapes
:2
Identity_33?
AssignVariableOp_33AssignVariableOp)assignvariableop_33_adam_dense_1_kernel_mIdentity_33:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_33n
Identity_34IdentityRestoreV2:tensors:34"/device:CPU:0*
T0*
_output_shapes
:2
Identity_34?
AssignVariableOp_34AssignVariableOp'assignvariableop_34_adam_dense_1_bias_mIdentity_34:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_34n
Identity_35IdentityRestoreV2:tensors:35"/device:CPU:0*
T0*
_output_shapes
:2
Identity_35?
AssignVariableOp_35AssignVariableOp(assignvariableop_35_adam_output_kernel_mIdentity_35:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_35n
Identity_36IdentityRestoreV2:tensors:36"/device:CPU:0*
T0*
_output_shapes
:2
Identity_36?
AssignVariableOp_36AssignVariableOp&assignvariableop_36_adam_output_bias_mIdentity_36:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_36n
Identity_37IdentityRestoreV2:tensors:37"/device:CPU:0*
T0*
_output_shapes
:2
Identity_37?
AssignVariableOp_37AssignVariableOp(assignvariableop_37_adam_conv1d_kernel_vIdentity_37:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_37n
Identity_38IdentityRestoreV2:tensors:38"/device:CPU:0*
T0*
_output_shapes
:2
Identity_38?
AssignVariableOp_38AssignVariableOp&assignvariableop_38_adam_conv1d_bias_vIdentity_38:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_38n
Identity_39IdentityRestoreV2:tensors:39"/device:CPU:0*
T0*
_output_shapes
:2
Identity_39?
AssignVariableOp_39AssignVariableOp(assignvariableop_39_adam_conv_1_kernel_vIdentity_39:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_39n
Identity_40IdentityRestoreV2:tensors:40"/device:CPU:0*
T0*
_output_shapes
:2
Identity_40?
AssignVariableOp_40AssignVariableOp&assignvariableop_40_adam_conv_1_bias_vIdentity_40:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_40n
Identity_41IdentityRestoreV2:tensors:41"/device:CPU:0*
T0*
_output_shapes
:2
Identity_41?
AssignVariableOp_41AssignVariableOp(assignvariableop_41_adam_conv_2_kernel_vIdentity_41:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_41n
Identity_42IdentityRestoreV2:tensors:42"/device:CPU:0*
T0*
_output_shapes
:2
Identity_42?
AssignVariableOp_42AssignVariableOp&assignvariableop_42_adam_conv_2_bias_vIdentity_42:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_42n
Identity_43IdentityRestoreV2:tensors:43"/device:CPU:0*
T0*
_output_shapes
:2
Identity_43?
AssignVariableOp_43AssignVariableOp(assignvariableop_43_adam_conv_3_kernel_vIdentity_43:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_43n
Identity_44IdentityRestoreV2:tensors:44"/device:CPU:0*
T0*
_output_shapes
:2
Identity_44?
AssignVariableOp_44AssignVariableOp&assignvariableop_44_adam_conv_3_bias_vIdentity_44:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_44n
Identity_45IdentityRestoreV2:tensors:45"/device:CPU:0*
T0*
_output_shapes
:2
Identity_45?
AssignVariableOp_45AssignVariableOp(assignvariableop_45_adam_conv_4_kernel_vIdentity_45:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_45n
Identity_46IdentityRestoreV2:tensors:46"/device:CPU:0*
T0*
_output_shapes
:2
Identity_46?
AssignVariableOp_46AssignVariableOp&assignvariableop_46_adam_conv_4_bias_vIdentity_46:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_46n
Identity_47IdentityRestoreV2:tensors:47"/device:CPU:0*
T0*
_output_shapes
:2
Identity_47?
AssignVariableOp_47AssignVariableOp)assignvariableop_47_adam_dense_1_kernel_vIdentity_47:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_47n
Identity_48IdentityRestoreV2:tensors:48"/device:CPU:0*
T0*
_output_shapes
:2
Identity_48?
AssignVariableOp_48AssignVariableOp'assignvariableop_48_adam_dense_1_bias_vIdentity_48:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_48n
Identity_49IdentityRestoreV2:tensors:49"/device:CPU:0*
T0*
_output_shapes
:2
Identity_49?
AssignVariableOp_49AssignVariableOp(assignvariableop_49_adam_output_kernel_vIdentity_49:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_49n
Identity_50IdentityRestoreV2:tensors:50"/device:CPU:0*
T0*
_output_shapes
:2
Identity_50?
AssignVariableOp_50AssignVariableOp&assignvariableop_50_adam_output_bias_vIdentity_50:output:0"/device:CPU:0*
_output_shapes
 *
dtype02
AssignVariableOp_509
NoOpNoOp"/device:CPU:0*
_output_shapes
 2
NoOp?	
Identity_51Identityfile_prefix^AssignVariableOp^AssignVariableOp_1^AssignVariableOp_10^AssignVariableOp_11^AssignVariableOp_12^AssignVariableOp_13^AssignVariableOp_14^AssignVariableOp_15^AssignVariableOp_16^AssignVariableOp_17^AssignVariableOp_18^AssignVariableOp_19^AssignVariableOp_2^AssignVariableOp_20^AssignVariableOp_21^AssignVariableOp_22^AssignVariableOp_23^AssignVariableOp_24^AssignVariableOp_25^AssignVariableOp_26^AssignVariableOp_27^AssignVariableOp_28^AssignVariableOp_29^AssignVariableOp_3^AssignVariableOp_30^AssignVariableOp_31^AssignVariableOp_32^AssignVariableOp_33^AssignVariableOp_34^AssignVariableOp_35^AssignVariableOp_36^AssignVariableOp_37^AssignVariableOp_38^AssignVariableOp_39^AssignVariableOp_4^AssignVariableOp_40^AssignVariableOp_41^AssignVariableOp_42^AssignVariableOp_43^AssignVariableOp_44^AssignVariableOp_45^AssignVariableOp_46^AssignVariableOp_47^AssignVariableOp_48^AssignVariableOp_49^AssignVariableOp_5^AssignVariableOp_50^AssignVariableOp_6^AssignVariableOp_7^AssignVariableOp_8^AssignVariableOp_9^NoOp"/device:CPU:0*
T0*
_output_shapes
: 2
Identity_51?	
Identity_52IdentityIdentity_51:output:0^AssignVariableOp^AssignVariableOp_1^AssignVariableOp_10^AssignVariableOp_11^AssignVariableOp_12^AssignVariableOp_13^AssignVariableOp_14^AssignVariableOp_15^AssignVariableOp_16^AssignVariableOp_17^AssignVariableOp_18^AssignVariableOp_19^AssignVariableOp_2^AssignVariableOp_20^AssignVariableOp_21^AssignVariableOp_22^AssignVariableOp_23^AssignVariableOp_24^AssignVariableOp_25^AssignVariableOp_26^AssignVariableOp_27^AssignVariableOp_28^AssignVariableOp_29^AssignVariableOp_3^AssignVariableOp_30^AssignVariableOp_31^AssignVariableOp_32^AssignVariableOp_33^AssignVariableOp_34^AssignVariableOp_35^AssignVariableOp_36^AssignVariableOp_37^AssignVariableOp_38^AssignVariableOp_39^AssignVariableOp_4^AssignVariableOp_40^AssignVariableOp_41^AssignVariableOp_42^AssignVariableOp_43^AssignVariableOp_44^AssignVariableOp_45^AssignVariableOp_46^AssignVariableOp_47^AssignVariableOp_48^AssignVariableOp_49^AssignVariableOp_5^AssignVariableOp_50^AssignVariableOp_6^AssignVariableOp_7^AssignVariableOp_8^AssignVariableOp_9*
T0*
_output_shapes
: 2
Identity_52"#
identity_52Identity_52:output:0*{
_input_shapesj
h: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : 2$
AssignVariableOpAssignVariableOp2(
AssignVariableOp_1AssignVariableOp_12*
AssignVariableOp_10AssignVariableOp_102*
AssignVariableOp_11AssignVariableOp_112*
AssignVariableOp_12AssignVariableOp_122*
AssignVariableOp_13AssignVariableOp_132*
AssignVariableOp_14AssignVariableOp_142*
AssignVariableOp_15AssignVariableOp_152*
AssignVariableOp_16AssignVariableOp_162*
AssignVariableOp_17AssignVariableOp_172*
AssignVariableOp_18AssignVariableOp_182*
AssignVariableOp_19AssignVariableOp_192(
AssignVariableOp_2AssignVariableOp_22*
AssignVariableOp_20AssignVariableOp_202*
AssignVariableOp_21AssignVariableOp_212*
AssignVariableOp_22AssignVariableOp_222*
AssignVariableOp_23AssignVariableOp_232*
AssignVariableOp_24AssignVariableOp_242*
AssignVariableOp_25AssignVariableOp_252*
AssignVariableOp_26AssignVariableOp_262*
AssignVariableOp_27AssignVariableOp_272*
AssignVariableOp_28AssignVariableOp_282*
AssignVariableOp_29AssignVariableOp_292(
AssignVariableOp_3AssignVariableOp_32*
AssignVariableOp_30AssignVariableOp_302*
AssignVariableOp_31AssignVariableOp_312*
AssignVariableOp_32AssignVariableOp_322*
AssignVariableOp_33AssignVariableOp_332*
AssignVariableOp_34AssignVariableOp_342*
AssignVariableOp_35AssignVariableOp_352*
AssignVariableOp_36AssignVariableOp_362*
AssignVariableOp_37AssignVariableOp_372*
AssignVariableOp_38AssignVariableOp_382*
AssignVariableOp_39AssignVariableOp_392(
AssignVariableOp_4AssignVariableOp_42*
AssignVariableOp_40AssignVariableOp_402*
AssignVariableOp_41AssignVariableOp_412*
AssignVariableOp_42AssignVariableOp_422*
AssignVariableOp_43AssignVariableOp_432*
AssignVariableOp_44AssignVariableOp_442*
AssignVariableOp_45AssignVariableOp_452*
AssignVariableOp_46AssignVariableOp_462*
AssignVariableOp_47AssignVariableOp_472*
AssignVariableOp_48AssignVariableOp_482*
AssignVariableOp_49AssignVariableOp_492(
AssignVariableOp_5AssignVariableOp_52*
AssignVariableOp_50AssignVariableOp_502(
AssignVariableOp_6AssignVariableOp_62(
AssignVariableOp_7AssignVariableOp_72(
AssignVariableOp_8AssignVariableOp_82(
AssignVariableOp_9AssignVariableOp_9:C ?

_output_shapes
: 
%
_user_specified_namefile_prefix
?
?
(__inference_DENSE_1_layer_call_fn_160887

inputs
unknown:	?@
	unknown_0:@
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *L
fGRE
C__inference_DENSE_1_layer_call_and_return_conditional_losses_1598262
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*+
_input_shapes
:??????????: : 22
StatefulPartitionedCallStatefulPartitionedCall:P L
(
_output_shapes
:??????????
 
_user_specified_nameinputs
?
?
/__inference_Proposed_Model_layer_call_fn_160635

inputs
unknown:(
	unknown_0:(
	unknown_1:(
	unknown_2:
	unknown_3:
	unknown_4:
	unknown_5:
	unknown_6:
	unknown_7: 
	unknown_8: 
	unknown_9:	?@

unknown_10:@

unknown_11:@

unknown_12:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0	unknown_1	unknown_2	unknown_3	unknown_4	unknown_5	unknown_6	unknown_7	unknown_8	unknown_9
unknown_10
unknown_11
unknown_12*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*0
_read_only_resource_inputs
	
*-
config_proto

CPU

GPU 2J 8? *S
fNRL
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_1598752
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?S
?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160125

inputs#
conv1d_160066:(
conv1d_160068:(#
conv_1_160071:(
conv_1_160073:#
conv_2_160077:
conv_2_160079:#
conv_3_160082:
conv_3_160084:#
conv_4_160087: 
conv_4_160089: !
dense_1_160095:	?@
dense_1_160097:@
output_160101:@
output_160103:
identity??CONV_1/StatefulPartitionedCall?CONV_2/StatefulPartitionedCall?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?CONV_3/StatefulPartitionedCall?CONV_4/StatefulPartitionedCall?DENSE_1/StatefulPartitionedCall?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?!DROPOUT_1/StatefulPartitionedCall?!DROPOUT_2/StatefulPartitionedCall?OUTPUT/StatefulPartitionedCall?conv1d/StatefulPartitionedCall?,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/StatefulPartitionedCallStatefulPartitionedCallinputsconv1d_160066conv1d_160068*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????(*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_conv1d_layer_call_and_return_conditional_losses_1596922 
conv1d/StatefulPartitionedCall?
CONV_1/StatefulPartitionedCallStatefulPartitionedCall'conv1d/StatefulPartitionedCall:output:0conv_1_160071conv_1_160073*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_1_layer_call_and_return_conditional_losses_1597142 
CONV_1/StatefulPartitionedCall?
POOLING_1/PartitionedCallPartitionedCall'CONV_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_1_layer_call_and_return_conditional_losses_1596422
POOLING_1/PartitionedCall?
CONV_2/StatefulPartitionedCallStatefulPartitionedCall"POOLING_1/PartitionedCall:output:0conv_2_160077conv_2_160079*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_2_layer_call_and_return_conditional_losses_1597432 
CONV_2/StatefulPartitionedCall?
CONV_3/StatefulPartitionedCallStatefulPartitionedCall'CONV_2/StatefulPartitionedCall:output:0conv_3_160082conv_3_160084*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_3_layer_call_and_return_conditional_losses_1597652 
CONV_3/StatefulPartitionedCall?
CONV_4/StatefulPartitionedCallStatefulPartitionedCall'CONV_3/StatefulPartitionedCall:output:0conv_4_160087conv_4_160089*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	 *$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_4_layer_call_and_return_conditional_losses_1597872 
CONV_4/StatefulPartitionedCall?
POOLING_2/PartitionedCallPartitionedCall'CONV_4/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_2_layer_call_and_return_conditional_losses_1596572
POOLING_2/PartitionedCall?
!DROPOUT_1/StatefulPartitionedCallStatefulPartitionedCall"POOLING_2/PartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_1599752#
!DROPOUT_1/StatefulPartitionedCall?
FC/PartitionedCallPartitionedCall*DROPOUT_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *(
_output_shapes
:??????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *G
fBR@
>__inference_FC_layer_call_and_return_conditional_losses_1598072
FC/PartitionedCall?
DENSE_1/StatefulPartitionedCallStatefulPartitionedCallFC/PartitionedCall:output:0dense_1_160095dense_1_160097*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *L
fGRE
C__inference_DENSE_1_layer_call_and_return_conditional_losses_1598262!
DENSE_1/StatefulPartitionedCall?
!DROPOUT_2/StatefulPartitionedCallStatefulPartitionedCall(DENSE_1/StatefulPartitionedCall:output:0"^DROPOUT_1/StatefulPartitionedCall*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_1599362#
!DROPOUT_2/StatefulPartitionedCall?
OUTPUT/StatefulPartitionedCallStatefulPartitionedCall*DROPOUT_2/StatefulPartitionedCall:output:0output_160101output_160103*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_OUTPUT_layer_call_and_return_conditional_losses_1598502 
OUTPUT/StatefulPartitionedCall?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv1d_160066*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv_2_160077*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpdense_1_160095*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentity'OUTPUT/StatefulPartitionedCall:output:0^CONV_1/StatefulPartitionedCall^CONV_2/StatefulPartitionedCall-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp^CONV_3/StatefulPartitionedCall^CONV_4/StatefulPartitionedCall ^DENSE_1/StatefulPartitionedCall.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp"^DROPOUT_1/StatefulPartitionedCall"^DROPOUT_2/StatefulPartitionedCall^OUTPUT/StatefulPartitionedCall^conv1d/StatefulPartitionedCall-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2@
CONV_1/StatefulPartitionedCallCONV_1/StatefulPartitionedCall2@
CONV_2/StatefulPartitionedCallCONV_2/StatefulPartitionedCall2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2@
CONV_3/StatefulPartitionedCallCONV_3/StatefulPartitionedCall2@
CONV_4/StatefulPartitionedCallCONV_4/StatefulPartitionedCall2B
DENSE_1/StatefulPartitionedCallDENSE_1/StatefulPartitionedCall2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2F
!DROPOUT_1/StatefulPartitionedCall!DROPOUT_1/StatefulPartitionedCall2F
!DROPOUT_2/StatefulPartitionedCall!DROPOUT_2/StatefulPartitionedCall2@
OUTPUT/StatefulPartitionedCallOUTPUT/StatefulPartitionedCall2@
conv1d/StatefulPartitionedCallconv1d/StatefulPartitionedCall2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?
c
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_159799

inputs

identity_1^
IdentityIdentityinputs*
T0*+
_output_shapes
:????????? 2

Identitym

Identity_1IdentityIdentity:output:0*
T0*+
_output_shapes
:????????? 2

Identity_1"!

identity_1Identity_1:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
?
B__inference_conv1d_layer_call_and_return_conditional_losses_159692

inputsA
+conv1d_expanddims_1_readvariableop_resource:(-
biasadd_readvariableop_resource:(
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOp?,conv1d/kernel/Regularizer/Abs/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????(*
paddingVALID*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????(*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:(*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????(2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????(2
Relu?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*+
_output_shapes
:?????????(2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?

?
B__inference_OUTPUT_layer_call_and_return_conditional_losses_159850

inputs0
matmul_readvariableop_resource:@-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?MatMul/ReadVariableOp?
MatMul/ReadVariableOpReadVariableOpmatmul_readvariableop_resource*
_output_shapes

:@*
dtype02
MatMul/ReadVariableOps
MatMulMatMulinputsMatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
MatMul?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddMatMul:product:0BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2	
BiasAdda
SoftmaxSoftmaxBiasAdd:output:0*
T0*'
_output_shapes
:?????????2	
Softmax?
IdentityIdentitySoftmax:softmax:0^BiasAdd/ReadVariableOp^MatMul/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:?????????@: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2.
MatMul/ReadVariableOpMatMul/ReadVariableOp:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?
?
C__inference_DENSE_1_layer_call_and_return_conditional_losses_159826

inputs1
matmul_readvariableop_resource:	?@-
biasadd_readvariableop_resource:@
identity??BiasAdd/ReadVariableOp?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?MatMul/ReadVariableOp?
MatMul/ReadVariableOpReadVariableOpmatmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02
MatMul/ReadVariableOps
MatMulMatMulinputsMatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
MatMul?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:@*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddMatMul:product:0BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2	
BiasAddX
ReluReluBiasAdd:output:0*
T0*'
_output_shapes
:?????????@2
Relu?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpmatmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp^MatMul/ReadVariableOp*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*+
_input_shapes
:??????????: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2.
MatMul/ReadVariableOpMatMul/ReadVariableOp:P L
(
_output_shapes
:??????????
 
_user_specified_nameinputs
?f
?
__inference__traced_save_161143
file_prefix,
(savev2_conv1d_kernel_read_readvariableop*
&savev2_conv1d_bias_read_readvariableop,
(savev2_conv_1_kernel_read_readvariableop*
&savev2_conv_1_bias_read_readvariableop,
(savev2_conv_2_kernel_read_readvariableop*
&savev2_conv_2_bias_read_readvariableop,
(savev2_conv_3_kernel_read_readvariableop*
&savev2_conv_3_bias_read_readvariableop,
(savev2_conv_4_kernel_read_readvariableop*
&savev2_conv_4_bias_read_readvariableop-
)savev2_dense_1_kernel_read_readvariableop+
'savev2_dense_1_bias_read_readvariableop,
(savev2_output_kernel_read_readvariableop*
&savev2_output_bias_read_readvariableop(
$savev2_adam_iter_read_readvariableop	*
&savev2_adam_beta_1_read_readvariableop*
&savev2_adam_beta_2_read_readvariableop)
%savev2_adam_decay_read_readvariableop1
-savev2_adam_learning_rate_read_readvariableop$
 savev2_total_read_readvariableop$
 savev2_count_read_readvariableop&
"savev2_total_1_read_readvariableop&
"savev2_count_1_read_readvariableop3
/savev2_adam_conv1d_kernel_m_read_readvariableop1
-savev2_adam_conv1d_bias_m_read_readvariableop3
/savev2_adam_conv_1_kernel_m_read_readvariableop1
-savev2_adam_conv_1_bias_m_read_readvariableop3
/savev2_adam_conv_2_kernel_m_read_readvariableop1
-savev2_adam_conv_2_bias_m_read_readvariableop3
/savev2_adam_conv_3_kernel_m_read_readvariableop1
-savev2_adam_conv_3_bias_m_read_readvariableop3
/savev2_adam_conv_4_kernel_m_read_readvariableop1
-savev2_adam_conv_4_bias_m_read_readvariableop4
0savev2_adam_dense_1_kernel_m_read_readvariableop2
.savev2_adam_dense_1_bias_m_read_readvariableop3
/savev2_adam_output_kernel_m_read_readvariableop1
-savev2_adam_output_bias_m_read_readvariableop3
/savev2_adam_conv1d_kernel_v_read_readvariableop1
-savev2_adam_conv1d_bias_v_read_readvariableop3
/savev2_adam_conv_1_kernel_v_read_readvariableop1
-savev2_adam_conv_1_bias_v_read_readvariableop3
/savev2_adam_conv_2_kernel_v_read_readvariableop1
-savev2_adam_conv_2_bias_v_read_readvariableop3
/savev2_adam_conv_3_kernel_v_read_readvariableop1
-savev2_adam_conv_3_bias_v_read_readvariableop3
/savev2_adam_conv_4_kernel_v_read_readvariableop1
-savev2_adam_conv_4_bias_v_read_readvariableop4
0savev2_adam_dense_1_kernel_v_read_readvariableop2
.savev2_adam_dense_1_bias_v_read_readvariableop3
/savev2_adam_output_kernel_v_read_readvariableop1
-savev2_adam_output_bias_v_read_readvariableop
savev2_const

identity_1??MergeV2Checkpoints?
StaticRegexFullMatchStaticRegexFullMatchfile_prefix"/device:CPU:**
_output_shapes
: *
pattern
^s3://.*2
StaticRegexFullMatchc
ConstConst"/device:CPU:**
_output_shapes
: *
dtype0*
valueB B.part2
Constl
Const_1Const"/device:CPU:**
_output_shapes
: *
dtype0*
valueB B
_temp/part2	
Const_1?
SelectSelectStaticRegexFullMatch:output:0Const:output:0Const_1:output:0"/device:CPU:**
T0*
_output_shapes
: 2
Selectt

StringJoin
StringJoinfile_prefixSelect:output:0"/device:CPU:**
N*
_output_shapes
: 2

StringJoinZ

num_shardsConst*
_output_shapes
: *
dtype0*
value	B :2

num_shards
ShardedFilename/shardConst"/device:CPU:0*
_output_shapes
: *
dtype0*
value	B : 2
ShardedFilename/shard?
ShardedFilenameShardedFilenameStringJoin:output:0ShardedFilename/shard:output:0num_shards:output:0"/device:CPU:0*
_output_shapes
: 2
ShardedFilename?
SaveV2/tensor_namesConst"/device:CPU:0*
_output_shapes
:4*
dtype0*?
value?B?4B6layer_with_weights-0/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-0/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-1/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-1/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-2/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-2/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-3/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-3/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-4/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-4/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-5/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-5/bias/.ATTRIBUTES/VARIABLE_VALUEB6layer_with_weights-6/kernel/.ATTRIBUTES/VARIABLE_VALUEB4layer_with_weights-6/bias/.ATTRIBUTES/VARIABLE_VALUEB)optimizer/iter/.ATTRIBUTES/VARIABLE_VALUEB+optimizer/beta_1/.ATTRIBUTES/VARIABLE_VALUEB+optimizer/beta_2/.ATTRIBUTES/VARIABLE_VALUEB*optimizer/decay/.ATTRIBUTES/VARIABLE_VALUEB2optimizer/learning_rate/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/0/total/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/0/count/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/1/total/.ATTRIBUTES/VARIABLE_VALUEB4keras_api/metrics/1/count/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-0/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-0/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-1/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-1/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-2/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-2/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-3/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-3/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-4/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-4/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-5/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-5/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-6/kernel/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-6/bias/.OPTIMIZER_SLOT/optimizer/m/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-0/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-0/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-1/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-1/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-2/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-2/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-3/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-3/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-4/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-4/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-5/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-5/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBRlayer_with_weights-6/kernel/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEBPlayer_with_weights-6/bias/.OPTIMIZER_SLOT/optimizer/v/.ATTRIBUTES/VARIABLE_VALUEB_CHECKPOINTABLE_OBJECT_GRAPH2
SaveV2/tensor_names?
SaveV2/shape_and_slicesConst"/device:CPU:0*
_output_shapes
:4*
dtype0*{
valuerBp4B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B B 2
SaveV2/shape_and_slices?
SaveV2SaveV2ShardedFilename:filename:0SaveV2/tensor_names:output:0 SaveV2/shape_and_slices:output:0(savev2_conv1d_kernel_read_readvariableop&savev2_conv1d_bias_read_readvariableop(savev2_conv_1_kernel_read_readvariableop&savev2_conv_1_bias_read_readvariableop(savev2_conv_2_kernel_read_readvariableop&savev2_conv_2_bias_read_readvariableop(savev2_conv_3_kernel_read_readvariableop&savev2_conv_3_bias_read_readvariableop(savev2_conv_4_kernel_read_readvariableop&savev2_conv_4_bias_read_readvariableop)savev2_dense_1_kernel_read_readvariableop'savev2_dense_1_bias_read_readvariableop(savev2_output_kernel_read_readvariableop&savev2_output_bias_read_readvariableop$savev2_adam_iter_read_readvariableop&savev2_adam_beta_1_read_readvariableop&savev2_adam_beta_2_read_readvariableop%savev2_adam_decay_read_readvariableop-savev2_adam_learning_rate_read_readvariableop savev2_total_read_readvariableop savev2_count_read_readvariableop"savev2_total_1_read_readvariableop"savev2_count_1_read_readvariableop/savev2_adam_conv1d_kernel_m_read_readvariableop-savev2_adam_conv1d_bias_m_read_readvariableop/savev2_adam_conv_1_kernel_m_read_readvariableop-savev2_adam_conv_1_bias_m_read_readvariableop/savev2_adam_conv_2_kernel_m_read_readvariableop-savev2_adam_conv_2_bias_m_read_readvariableop/savev2_adam_conv_3_kernel_m_read_readvariableop-savev2_adam_conv_3_bias_m_read_readvariableop/savev2_adam_conv_4_kernel_m_read_readvariableop-savev2_adam_conv_4_bias_m_read_readvariableop0savev2_adam_dense_1_kernel_m_read_readvariableop.savev2_adam_dense_1_bias_m_read_readvariableop/savev2_adam_output_kernel_m_read_readvariableop-savev2_adam_output_bias_m_read_readvariableop/savev2_adam_conv1d_kernel_v_read_readvariableop-savev2_adam_conv1d_bias_v_read_readvariableop/savev2_adam_conv_1_kernel_v_read_readvariableop-savev2_adam_conv_1_bias_v_read_readvariableop/savev2_adam_conv_2_kernel_v_read_readvariableop-savev2_adam_conv_2_bias_v_read_readvariableop/savev2_adam_conv_3_kernel_v_read_readvariableop-savev2_adam_conv_3_bias_v_read_readvariableop/savev2_adam_conv_4_kernel_v_read_readvariableop-savev2_adam_conv_4_bias_v_read_readvariableop0savev2_adam_dense_1_kernel_v_read_readvariableop.savev2_adam_dense_1_bias_v_read_readvariableop/savev2_adam_output_kernel_v_read_readvariableop-savev2_adam_output_bias_v_read_readvariableopsavev2_const"/device:CPU:0*
_output_shapes
 *B
dtypes8
624	2
SaveV2?
&MergeV2Checkpoints/checkpoint_prefixesPackShardedFilename:filename:0^SaveV2"/device:CPU:0*
N*
T0*
_output_shapes
:2(
&MergeV2Checkpoints/checkpoint_prefixes?
MergeV2CheckpointsMergeV2Checkpoints/MergeV2Checkpoints/checkpoint_prefixes:output:0file_prefix"/device:CPU:0*
_output_shapes
 2
MergeV2Checkpointsr
IdentityIdentityfile_prefix^MergeV2Checkpoints"/device:CPU:0*
T0*
_output_shapes
: 2

Identitym

Identity_1IdentityIdentity:output:0^MergeV2Checkpoints*
T0*
_output_shapes
: 2

Identity_1"!

identity_1Identity_1:output:0*?
_input_shapes?
?: :(:(:(:::::: : :	?@:@:@:: : : : : : : : : :(:(:(:::::: : :	?@:@:@::(:(:(:::::: : :	?@:@:@:: 2(
MergeV2CheckpointsMergeV2Checkpoints:C ?

_output_shapes
: 
%
_user_specified_namefile_prefix:($
"
_output_shapes
:(: 

_output_shapes
:(:($
"
_output_shapes
:(: 

_output_shapes
::($
"
_output_shapes
:: 

_output_shapes
::($
"
_output_shapes
:: 

_output_shapes
::(	$
"
_output_shapes
: : 


_output_shapes
: :%!

_output_shapes
:	?@: 

_output_shapes
:@:$ 

_output_shapes

:@: 

_output_shapes
::

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :

_output_shapes
: :($
"
_output_shapes
:(: 

_output_shapes
:(:($
"
_output_shapes
:(: 

_output_shapes
::($
"
_output_shapes
:: 

_output_shapes
::($
"
_output_shapes
:: 

_output_shapes
::( $
"
_output_shapes
: : !

_output_shapes
: :%"!

_output_shapes
:	?@: #

_output_shapes
:@:$$ 

_output_shapes

:@: %

_output_shapes
::(&$
"
_output_shapes
:(: '

_output_shapes
:(:(($
"
_output_shapes
:(: )

_output_shapes
::(*$
"
_output_shapes
:: +

_output_shapes
::(,$
"
_output_shapes
:: -

_output_shapes
::(.$
"
_output_shapes
: : /

_output_shapes
: :%0!

_output_shapes
:	?@: 1

_output_shapes
:@:$2 

_output_shapes

:@: 3

_output_shapes
::4

_output_shapes
: 
?
?
'__inference_conv1d_layer_call_fn_160705

inputs
unknown:(
	unknown_0:(
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????(*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_conv1d_layer_call_and_return_conditional_losses_1596922
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*+
_output_shapes
:?????????(2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????: : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????
 
_user_specified_nameinputs
?
?
$__inference_signature_wrapper_160372
conv1d_input
unknown:(
	unknown_0:(
	unknown_1:(
	unknown_2:
	unknown_3:
	unknown_4:
	unknown_5:
	unknown_6:
	unknown_7: 
	unknown_8: 
	unknown_9:	?@

unknown_10:@

unknown_11:@

unknown_12:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallconv1d_inputunknown	unknown_0	unknown_1	unknown_2	unknown_3	unknown_4	unknown_5	unknown_6	unknown_7	unknown_8	unknown_9
unknown_10
unknown_11
unknown_12*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*0
_read_only_resource_inputs
	
*-
config_proto

CPU

GPU 2J 8? **
f%R#
!__inference__wrapped_model_1596332
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 22
StatefulPartitionedCallStatefulPartitionedCall:Y U
+
_output_shapes
:?????????
&
_user_specified_nameconv1d_input
?
?
B__inference_CONV_3_layer_call_and_return_conditional_losses_160783

inputsA
+conv1d_expanddims_1_readvariableop_resource:-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
Relu?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????	2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
c
*__inference_DROPOUT_1_layer_call_fn_160844

inputs
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_1599752
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*+
_output_shapes
:????????? 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
?
B__inference_CONV_4_layer_call_and_return_conditional_losses_160808

inputsA
+conv1d_expanddims_1_readvariableop_resource: -
biasadd_readvariableop_resource: 
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
: *
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
: 2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	 *
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????	 *
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
: *
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	 2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????	 2
Relu?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????	 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs
?
d
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_160904

inputs
identity?c
dropout/ConstConst*
_output_shapes
: *
dtype0*
valueB
 *   @2
dropout/Consts
dropout/MulMulinputsdropout/Const:output:0*
T0*'
_output_shapes
:?????????@2
dropout/MulT
dropout/ShapeShapeinputs*
T0*
_output_shapes
:2
dropout/Shape?
$dropout/random_uniform/RandomUniformRandomUniformdropout/Shape:output:0*
T0*'
_output_shapes
:?????????@*
dtype02&
$dropout/random_uniform/RandomUniformu
dropout/GreaterEqual/yConst*
_output_shapes
: *
dtype0*
valueB
 *   ?2
dropout/GreaterEqual/y?
dropout/GreaterEqualGreaterEqual-dropout/random_uniform/RandomUniform:output:0dropout/GreaterEqual/y:output:0*
T0*'
_output_shapes
:?????????@2
dropout/GreaterEqual
dropout/CastCastdropout/GreaterEqual:z:0*

DstT0*

SrcT0
*'
_output_shapes
:?????????@2
dropout/Castz
dropout/Mul_1Muldropout/Mul:z:0dropout/Cast:y:0*
T0*'
_output_shapes
:?????????@2
dropout/Mul_1e
IdentityIdentitydropout/Mul_1:z:0*
T0*'
_output_shapes
:?????????@2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*&
_input_shapes
:?????????@:O K
'
_output_shapes
:?????????@
 
_user_specified_nameinputs
?S
?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160313
conv1d_input#
conv1d_160254:(
conv1d_160256:(#
conv_1_160259:(
conv_1_160261:#
conv_2_160265:
conv_2_160267:#
conv_3_160270:
conv_3_160272:#
conv_4_160275: 
conv_4_160277: !
dense_1_160283:	?@
dense_1_160285:@
output_160289:@
output_160291:
identity??CONV_1/StatefulPartitionedCall?CONV_2/StatefulPartitionedCall?,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?CONV_3/StatefulPartitionedCall?CONV_4/StatefulPartitionedCall?DENSE_1/StatefulPartitionedCall?-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?!DROPOUT_1/StatefulPartitionedCall?!DROPOUT_2/StatefulPartitionedCall?OUTPUT/StatefulPartitionedCall?conv1d/StatefulPartitionedCall?,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/StatefulPartitionedCallStatefulPartitionedCallconv1d_inputconv1d_160254conv1d_160256*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????(*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_conv1d_layer_call_and_return_conditional_losses_1596922 
conv1d/StatefulPartitionedCall?
CONV_1/StatefulPartitionedCallStatefulPartitionedCall'conv1d/StatefulPartitionedCall:output:0conv_1_160259conv_1_160261*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_1_layer_call_and_return_conditional_losses_1597142 
CONV_1/StatefulPartitionedCall?
POOLING_1/PartitionedCallPartitionedCall'CONV_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_1_layer_call_and_return_conditional_losses_1596422
POOLING_1/PartitionedCall?
CONV_2/StatefulPartitionedCallStatefulPartitionedCall"POOLING_1/PartitionedCall:output:0conv_2_160265conv_2_160267*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_2_layer_call_and_return_conditional_losses_1597432 
CONV_2/StatefulPartitionedCall?
CONV_3/StatefulPartitionedCallStatefulPartitionedCall'CONV_2/StatefulPartitionedCall:output:0conv_3_160270conv_3_160272*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_3_layer_call_and_return_conditional_losses_1597652 
CONV_3/StatefulPartitionedCall?
CONV_4/StatefulPartitionedCallStatefulPartitionedCall'CONV_3/StatefulPartitionedCall:output:0conv_4_160275conv_4_160277*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????	 *$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_4_layer_call_and_return_conditional_losses_1597872 
CONV_4/StatefulPartitionedCall?
POOLING_2/PartitionedCallPartitionedCall'CONV_4/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_POOLING_2_layer_call_and_return_conditional_losses_1596572
POOLING_2/PartitionedCall?
!DROPOUT_1/StatefulPartitionedCallStatefulPartitionedCall"POOLING_2/PartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_1599752#
!DROPOUT_1/StatefulPartitionedCall?
FC/PartitionedCallPartitionedCall*DROPOUT_1/StatefulPartitionedCall:output:0*
Tin
2*
Tout
2*
_collective_manager_ids
 *(
_output_shapes
:??????????* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *G
fBR@
>__inference_FC_layer_call_and_return_conditional_losses_1598072
FC/PartitionedCall?
DENSE_1/StatefulPartitionedCallStatefulPartitionedCallFC/PartitionedCall:output:0dense_1_160283dense_1_160285*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *L
fGRE
C__inference_DENSE_1_layer_call_and_return_conditional_losses_1598262!
DENSE_1/StatefulPartitionedCall?
!DROPOUT_2/StatefulPartitionedCallStatefulPartitionedCall(DENSE_1/StatefulPartitionedCall:output:0"^DROPOUT_1/StatefulPartitionedCall*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????@* 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_1599362#
!DROPOUT_2/StatefulPartitionedCall?
OUTPUT/StatefulPartitionedCallStatefulPartitionedCall*DROPOUT_2/StatefulPartitionedCall:output:0output_160289output_160291*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_OUTPUT_layer_call_and_return_conditional_losses_1598502 
OUTPUT/StatefulPartitionedCall?
,conv1d/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv1d_160254*"
_output_shapes
:(*
dtype02.
,conv1d/kernel/Regularizer/Abs/ReadVariableOp?
conv1d/kernel/Regularizer/AbsAbs4conv1d/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:(2
conv1d/kernel/Regularizer/Abs?
conv1d/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
conv1d/kernel/Regularizer/Const?
conv1d/kernel/Regularizer/SumSum!conv1d/kernel/Regularizer/Abs:y:0(conv1d/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/Sum?
conv1d/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
conv1d/kernel/Regularizer/mul/x?
conv1d/kernel/Regularizer/mulMul(conv1d/kernel/Regularizer/mul/x:output:0&conv1d/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
conv1d/kernel/Regularizer/mul?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpconv_2_160265*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOpReadVariableOpdense_1_160283*
_output_shapes
:	?@*
dtype02/
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp?
DENSE_1/kernel/Regularizer/AbsAbs5DENSE_1/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*
_output_shapes
:	?@2 
DENSE_1/kernel/Regularizer/Abs?
 DENSE_1/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*
valueB"       2"
 DENSE_1/kernel/Regularizer/Const?
DENSE_1/kernel/Regularizer/SumSum"DENSE_1/kernel/Regularizer/Abs:y:0)DENSE_1/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/Sum?
 DENSE_1/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82"
 DENSE_1/kernel/Regularizer/mul/x?
DENSE_1/kernel/Regularizer/mulMul)DENSE_1/kernel/Regularizer/mul/x:output:0'DENSE_1/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2 
DENSE_1/kernel/Regularizer/mul?
IdentityIdentity'OUTPUT/StatefulPartitionedCall:output:0^CONV_1/StatefulPartitionedCall^CONV_2/StatefulPartitionedCall-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp^CONV_3/StatefulPartitionedCall^CONV_4/StatefulPartitionedCall ^DENSE_1/StatefulPartitionedCall.^DENSE_1/kernel/Regularizer/Abs/ReadVariableOp"^DROPOUT_1/StatefulPartitionedCall"^DROPOUT_2/StatefulPartitionedCall^OUTPUT/StatefulPartitionedCall^conv1d/StatefulPartitionedCall-^conv1d/kernel/Regularizer/Abs/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2@
CONV_1/StatefulPartitionedCallCONV_1/StatefulPartitionedCall2@
CONV_2/StatefulPartitionedCallCONV_2/StatefulPartitionedCall2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp2@
CONV_3/StatefulPartitionedCallCONV_3/StatefulPartitionedCall2@
CONV_4/StatefulPartitionedCallCONV_4/StatefulPartitionedCall2B
DENSE_1/StatefulPartitionedCallDENSE_1/StatefulPartitionedCall2^
-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp-DENSE_1/kernel/Regularizer/Abs/ReadVariableOp2F
!DROPOUT_1/StatefulPartitionedCall!DROPOUT_1/StatefulPartitionedCall2F
!DROPOUT_2/StatefulPartitionedCall!DROPOUT_2/StatefulPartitionedCall2@
OUTPUT/StatefulPartitionedCallOUTPUT/StatefulPartitionedCall2@
conv1d/StatefulPartitionedCallconv1d/StatefulPartitionedCall2\
,conv1d/kernel/Regularizer/Abs/ReadVariableOp,conv1d/kernel/Regularizer/Abs/ReadVariableOp:Y U
+
_output_shapes
:?????????
&
_user_specified_nameconv1d_input
??
?
!__inference__wrapped_model_159633
conv1d_inputW
Aproposed_model_conv1d_conv1d_expanddims_1_readvariableop_resource:(C
5proposed_model_conv1d_biasadd_readvariableop_resource:(W
Aproposed_model_conv_1_conv1d_expanddims_1_readvariableop_resource:(C
5proposed_model_conv_1_biasadd_readvariableop_resource:W
Aproposed_model_conv_2_conv1d_expanddims_1_readvariableop_resource:C
5proposed_model_conv_2_biasadd_readvariableop_resource:W
Aproposed_model_conv_3_conv1d_expanddims_1_readvariableop_resource:C
5proposed_model_conv_3_biasadd_readvariableop_resource:W
Aproposed_model_conv_4_conv1d_expanddims_1_readvariableop_resource: C
5proposed_model_conv_4_biasadd_readvariableop_resource: H
5proposed_model_dense_1_matmul_readvariableop_resource:	?@D
6proposed_model_dense_1_biasadd_readvariableop_resource:@F
4proposed_model_output_matmul_readvariableop_resource:@C
5proposed_model_output_biasadd_readvariableop_resource:
identity??,Proposed_Model/CONV_1/BiasAdd/ReadVariableOp?8Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOp?,Proposed_Model/CONV_2/BiasAdd/ReadVariableOp?8Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOp?,Proposed_Model/CONV_3/BiasAdd/ReadVariableOp?8Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOp?,Proposed_Model/CONV_4/BiasAdd/ReadVariableOp?8Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOp?-Proposed_Model/DENSE_1/BiasAdd/ReadVariableOp?,Proposed_Model/DENSE_1/MatMul/ReadVariableOp?,Proposed_Model/OUTPUT/BiasAdd/ReadVariableOp?+Proposed_Model/OUTPUT/MatMul/ReadVariableOp?,Proposed_Model/conv1d/BiasAdd/ReadVariableOp?8Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOp?
+Proposed_Model/conv1d/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2-
+Proposed_Model/conv1d/conv1d/ExpandDims/dim?
'Proposed_Model/conv1d/conv1d/ExpandDims
ExpandDimsconv1d_input4Proposed_Model/conv1d/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2)
'Proposed_Model/conv1d/conv1d/ExpandDims?
8Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOpReadVariableOpAproposed_model_conv1d_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02:
8Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOp?
-Proposed_Model/conv1d/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2/
-Proposed_Model/conv1d/conv1d/ExpandDims_1/dim?
)Proposed_Model/conv1d/conv1d/ExpandDims_1
ExpandDims@Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOp:value:06Proposed_Model/conv1d/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2+
)Proposed_Model/conv1d/conv1d/ExpandDims_1?
Proposed_Model/conv1d/conv1dConv2D0Proposed_Model/conv1d/conv1d/ExpandDims:output:02Proposed_Model/conv1d/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????(*
paddingVALID*
strides
2
Proposed_Model/conv1d/conv1d?
$Proposed_Model/conv1d/conv1d/SqueezeSqueeze%Proposed_Model/conv1d/conv1d:output:0*
T0*+
_output_shapes
:?????????(*
squeeze_dims

?????????2&
$Proposed_Model/conv1d/conv1d/Squeeze?
,Proposed_Model/conv1d/BiasAdd/ReadVariableOpReadVariableOp5proposed_model_conv1d_biasadd_readvariableop_resource*
_output_shapes
:(*
dtype02.
,Proposed_Model/conv1d/BiasAdd/ReadVariableOp?
Proposed_Model/conv1d/BiasAddBiasAdd-Proposed_Model/conv1d/conv1d/Squeeze:output:04Proposed_Model/conv1d/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????(2
Proposed_Model/conv1d/BiasAdd?
Proposed_Model/conv1d/ReluRelu&Proposed_Model/conv1d/BiasAdd:output:0*
T0*+
_output_shapes
:?????????(2
Proposed_Model/conv1d/Relu?
+Proposed_Model/CONV_1/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2-
+Proposed_Model/CONV_1/conv1d/ExpandDims/dim?
'Proposed_Model/CONV_1/conv1d/ExpandDims
ExpandDims(Proposed_Model/conv1d/Relu:activations:04Proposed_Model/CONV_1/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????(2)
'Proposed_Model/CONV_1/conv1d/ExpandDims?
8Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOpReadVariableOpAproposed_model_conv_1_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:(*
dtype02:
8Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOp?
-Proposed_Model/CONV_1/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2/
-Proposed_Model/CONV_1/conv1d/ExpandDims_1/dim?
)Proposed_Model/CONV_1/conv1d/ExpandDims_1
ExpandDims@Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOp:value:06Proposed_Model/CONV_1/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:(2+
)Proposed_Model/CONV_1/conv1d/ExpandDims_1?
Proposed_Model/CONV_1/conv1dConv2D0Proposed_Model/CONV_1/conv1d/ExpandDims:output:02Proposed_Model/CONV_1/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????*
paddingSAME*
strides
2
Proposed_Model/CONV_1/conv1d?
$Proposed_Model/CONV_1/conv1d/SqueezeSqueeze%Proposed_Model/CONV_1/conv1d:output:0*
T0*+
_output_shapes
:?????????*
squeeze_dims

?????????2&
$Proposed_Model/CONV_1/conv1d/Squeeze?
,Proposed_Model/CONV_1/BiasAdd/ReadVariableOpReadVariableOp5proposed_model_conv_1_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02.
,Proposed_Model/CONV_1/BiasAdd/ReadVariableOp?
Proposed_Model/CONV_1/BiasAddBiasAdd-Proposed_Model/CONV_1/conv1d/Squeeze:output:04Proposed_Model/CONV_1/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????2
Proposed_Model/CONV_1/BiasAdd?
Proposed_Model/CONV_1/ReluRelu&Proposed_Model/CONV_1/BiasAdd:output:0*
T0*+
_output_shapes
:?????????2
Proposed_Model/CONV_1/Relu?
'Proposed_Model/POOLING_1/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2)
'Proposed_Model/POOLING_1/ExpandDims/dim?
#Proposed_Model/POOLING_1/ExpandDims
ExpandDims(Proposed_Model/CONV_1/Relu:activations:00Proposed_Model/POOLING_1/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????2%
#Proposed_Model/POOLING_1/ExpandDims?
 Proposed_Model/POOLING_1/MaxPoolMaxPool,Proposed_Model/POOLING_1/ExpandDims:output:0*/
_output_shapes
:?????????	*
ksize
*
paddingVALID*
strides
2"
 Proposed_Model/POOLING_1/MaxPool?
 Proposed_Model/POOLING_1/SqueezeSqueeze)Proposed_Model/POOLING_1/MaxPool:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims
2"
 Proposed_Model/POOLING_1/Squeeze?
+Proposed_Model/CONV_2/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2-
+Proposed_Model/CONV_2/conv1d/ExpandDims/dim?
'Proposed_Model/CONV_2/conv1d/ExpandDims
ExpandDims)Proposed_Model/POOLING_1/Squeeze:output:04Proposed_Model/CONV_2/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2)
'Proposed_Model/CONV_2/conv1d/ExpandDims?
8Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOpReadVariableOpAproposed_model_conv_2_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02:
8Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOp?
-Proposed_Model/CONV_2/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2/
-Proposed_Model/CONV_2/conv1d/ExpandDims_1/dim?
)Proposed_Model/CONV_2/conv1d/ExpandDims_1
ExpandDims@Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOp:value:06Proposed_Model/CONV_2/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2+
)Proposed_Model/CONV_2/conv1d/ExpandDims_1?
Proposed_Model/CONV_2/conv1dConv2D0Proposed_Model/CONV_2/conv1d/ExpandDims:output:02Proposed_Model/CONV_2/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
Proposed_Model/CONV_2/conv1d?
$Proposed_Model/CONV_2/conv1d/SqueezeSqueeze%Proposed_Model/CONV_2/conv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2&
$Proposed_Model/CONV_2/conv1d/Squeeze?
,Proposed_Model/CONV_2/BiasAdd/ReadVariableOpReadVariableOp5proposed_model_conv_2_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02.
,Proposed_Model/CONV_2/BiasAdd/ReadVariableOp?
Proposed_Model/CONV_2/BiasAddBiasAdd-Proposed_Model/CONV_2/conv1d/Squeeze:output:04Proposed_Model/CONV_2/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2
Proposed_Model/CONV_2/BiasAdd?
Proposed_Model/CONV_2/ReluRelu&Proposed_Model/CONV_2/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
Proposed_Model/CONV_2/Relu?
+Proposed_Model/CONV_3/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2-
+Proposed_Model/CONV_3/conv1d/ExpandDims/dim?
'Proposed_Model/CONV_3/conv1d/ExpandDims
ExpandDims(Proposed_Model/CONV_2/Relu:activations:04Proposed_Model/CONV_3/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2)
'Proposed_Model/CONV_3/conv1d/ExpandDims?
8Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOpReadVariableOpAproposed_model_conv_3_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02:
8Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOp?
-Proposed_Model/CONV_3/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2/
-Proposed_Model/CONV_3/conv1d/ExpandDims_1/dim?
)Proposed_Model/CONV_3/conv1d/ExpandDims_1
ExpandDims@Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOp:value:06Proposed_Model/CONV_3/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2+
)Proposed_Model/CONV_3/conv1d/ExpandDims_1?
Proposed_Model/CONV_3/conv1dConv2D0Proposed_Model/CONV_3/conv1d/ExpandDims:output:02Proposed_Model/CONV_3/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
Proposed_Model/CONV_3/conv1d?
$Proposed_Model/CONV_3/conv1d/SqueezeSqueeze%Proposed_Model/CONV_3/conv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2&
$Proposed_Model/CONV_3/conv1d/Squeeze?
,Proposed_Model/CONV_3/BiasAdd/ReadVariableOpReadVariableOp5proposed_model_conv_3_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02.
,Proposed_Model/CONV_3/BiasAdd/ReadVariableOp?
Proposed_Model/CONV_3/BiasAddBiasAdd-Proposed_Model/CONV_3/conv1d/Squeeze:output:04Proposed_Model/CONV_3/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2
Proposed_Model/CONV_3/BiasAdd?
Proposed_Model/CONV_3/ReluRelu&Proposed_Model/CONV_3/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
Proposed_Model/CONV_3/Relu?
+Proposed_Model/CONV_4/conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2-
+Proposed_Model/CONV_4/conv1d/ExpandDims/dim?
'Proposed_Model/CONV_4/conv1d/ExpandDims
ExpandDims(Proposed_Model/CONV_3/Relu:activations:04Proposed_Model/CONV_4/conv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2)
'Proposed_Model/CONV_4/conv1d/ExpandDims?
8Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOpReadVariableOpAproposed_model_conv_4_conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
: *
dtype02:
8Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOp?
-Proposed_Model/CONV_4/conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2/
-Proposed_Model/CONV_4/conv1d/ExpandDims_1/dim?
)Proposed_Model/CONV_4/conv1d/ExpandDims_1
ExpandDims@Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOp:value:06Proposed_Model/CONV_4/conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
: 2+
)Proposed_Model/CONV_4/conv1d/ExpandDims_1?
Proposed_Model/CONV_4/conv1dConv2D0Proposed_Model/CONV_4/conv1d/ExpandDims:output:02Proposed_Model/CONV_4/conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	 *
paddingSAME*
strides
2
Proposed_Model/CONV_4/conv1d?
$Proposed_Model/CONV_4/conv1d/SqueezeSqueeze%Proposed_Model/CONV_4/conv1d:output:0*
T0*+
_output_shapes
:?????????	 *
squeeze_dims

?????????2&
$Proposed_Model/CONV_4/conv1d/Squeeze?
,Proposed_Model/CONV_4/BiasAdd/ReadVariableOpReadVariableOp5proposed_model_conv_4_biasadd_readvariableop_resource*
_output_shapes
: *
dtype02.
,Proposed_Model/CONV_4/BiasAdd/ReadVariableOp?
Proposed_Model/CONV_4/BiasAddBiasAdd-Proposed_Model/CONV_4/conv1d/Squeeze:output:04Proposed_Model/CONV_4/BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	 2
Proposed_Model/CONV_4/BiasAdd?
Proposed_Model/CONV_4/ReluRelu&Proposed_Model/CONV_4/BiasAdd:output:0*
T0*+
_output_shapes
:?????????	 2
Proposed_Model/CONV_4/Relu?
'Proposed_Model/POOLING_2/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
value	B :2)
'Proposed_Model/POOLING_2/ExpandDims/dim?
#Proposed_Model/POOLING_2/ExpandDims
ExpandDims(Proposed_Model/CONV_4/Relu:activations:00Proposed_Model/POOLING_2/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	 2%
#Proposed_Model/POOLING_2/ExpandDims?
 Proposed_Model/POOLING_2/MaxPoolMaxPool,Proposed_Model/POOLING_2/ExpandDims:output:0*/
_output_shapes
:????????? *
ksize
*
paddingVALID*
strides
2"
 Proposed_Model/POOLING_2/MaxPool?
 Proposed_Model/POOLING_2/SqueezeSqueeze)Proposed_Model/POOLING_2/MaxPool:output:0*
T0*+
_output_shapes
:????????? *
squeeze_dims
2"
 Proposed_Model/POOLING_2/Squeeze?
!Proposed_Model/DROPOUT_1/IdentityIdentity)Proposed_Model/POOLING_2/Squeeze:output:0*
T0*+
_output_shapes
:????????? 2#
!Proposed_Model/DROPOUT_1/Identity?
Proposed_Model/FC/ConstConst*
_output_shapes
:*
dtype0*
valueB"?????   2
Proposed_Model/FC/Const?
Proposed_Model/FC/ReshapeReshape*Proposed_Model/DROPOUT_1/Identity:output:0 Proposed_Model/FC/Const:output:0*
T0*(
_output_shapes
:??????????2
Proposed_Model/FC/Reshape?
,Proposed_Model/DENSE_1/MatMul/ReadVariableOpReadVariableOp5proposed_model_dense_1_matmul_readvariableop_resource*
_output_shapes
:	?@*
dtype02.
,Proposed_Model/DENSE_1/MatMul/ReadVariableOp?
Proposed_Model/DENSE_1/MatMulMatMul"Proposed_Model/FC/Reshape:output:04Proposed_Model/DENSE_1/MatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2
Proposed_Model/DENSE_1/MatMul?
-Proposed_Model/DENSE_1/BiasAdd/ReadVariableOpReadVariableOp6proposed_model_dense_1_biasadd_readvariableop_resource*
_output_shapes
:@*
dtype02/
-Proposed_Model/DENSE_1/BiasAdd/ReadVariableOp?
Proposed_Model/DENSE_1/BiasAddBiasAdd'Proposed_Model/DENSE_1/MatMul:product:05Proposed_Model/DENSE_1/BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????@2 
Proposed_Model/DENSE_1/BiasAdd?
Proposed_Model/DENSE_1/ReluRelu'Proposed_Model/DENSE_1/BiasAdd:output:0*
T0*'
_output_shapes
:?????????@2
Proposed_Model/DENSE_1/Relu?
!Proposed_Model/DROPOUT_2/IdentityIdentity)Proposed_Model/DENSE_1/Relu:activations:0*
T0*'
_output_shapes
:?????????@2#
!Proposed_Model/DROPOUT_2/Identity?
+Proposed_Model/OUTPUT/MatMul/ReadVariableOpReadVariableOp4proposed_model_output_matmul_readvariableop_resource*
_output_shapes

:@*
dtype02-
+Proposed_Model/OUTPUT/MatMul/ReadVariableOp?
Proposed_Model/OUTPUT/MatMulMatMul*Proposed_Model/DROPOUT_2/Identity:output:03Proposed_Model/OUTPUT/MatMul/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
Proposed_Model/OUTPUT/MatMul?
,Proposed_Model/OUTPUT/BiasAdd/ReadVariableOpReadVariableOp5proposed_model_output_biasadd_readvariableop_resource*
_output_shapes
:*
dtype02.
,Proposed_Model/OUTPUT/BiasAdd/ReadVariableOp?
Proposed_Model/OUTPUT/BiasAddBiasAdd&Proposed_Model/OUTPUT/MatMul:product:04Proposed_Model/OUTPUT/BiasAdd/ReadVariableOp:value:0*
T0*'
_output_shapes
:?????????2
Proposed_Model/OUTPUT/BiasAdd?
Proposed_Model/OUTPUT/SoftmaxSoftmax&Proposed_Model/OUTPUT/BiasAdd:output:0*
T0*'
_output_shapes
:?????????2
Proposed_Model/OUTPUT/Softmax?
IdentityIdentity'Proposed_Model/OUTPUT/Softmax:softmax:0-^Proposed_Model/CONV_1/BiasAdd/ReadVariableOp9^Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOp-^Proposed_Model/CONV_2/BiasAdd/ReadVariableOp9^Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOp-^Proposed_Model/CONV_3/BiasAdd/ReadVariableOp9^Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOp-^Proposed_Model/CONV_4/BiasAdd/ReadVariableOp9^Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOp.^Proposed_Model/DENSE_1/BiasAdd/ReadVariableOp-^Proposed_Model/DENSE_1/MatMul/ReadVariableOp-^Proposed_Model/OUTPUT/BiasAdd/ReadVariableOp,^Proposed_Model/OUTPUT/MatMul/ReadVariableOp-^Proposed_Model/conv1d/BiasAdd/ReadVariableOp9^Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOp*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 2\
,Proposed_Model/CONV_1/BiasAdd/ReadVariableOp,Proposed_Model/CONV_1/BiasAdd/ReadVariableOp2t
8Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOp8Proposed_Model/CONV_1/conv1d/ExpandDims_1/ReadVariableOp2\
,Proposed_Model/CONV_2/BiasAdd/ReadVariableOp,Proposed_Model/CONV_2/BiasAdd/ReadVariableOp2t
8Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOp8Proposed_Model/CONV_2/conv1d/ExpandDims_1/ReadVariableOp2\
,Proposed_Model/CONV_3/BiasAdd/ReadVariableOp,Proposed_Model/CONV_3/BiasAdd/ReadVariableOp2t
8Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOp8Proposed_Model/CONV_3/conv1d/ExpandDims_1/ReadVariableOp2\
,Proposed_Model/CONV_4/BiasAdd/ReadVariableOp,Proposed_Model/CONV_4/BiasAdd/ReadVariableOp2t
8Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOp8Proposed_Model/CONV_4/conv1d/ExpandDims_1/ReadVariableOp2^
-Proposed_Model/DENSE_1/BiasAdd/ReadVariableOp-Proposed_Model/DENSE_1/BiasAdd/ReadVariableOp2\
,Proposed_Model/DENSE_1/MatMul/ReadVariableOp,Proposed_Model/DENSE_1/MatMul/ReadVariableOp2\
,Proposed_Model/OUTPUT/BiasAdd/ReadVariableOp,Proposed_Model/OUTPUT/BiasAdd/ReadVariableOp2Z
+Proposed_Model/OUTPUT/MatMul/ReadVariableOp+Proposed_Model/OUTPUT/MatMul/ReadVariableOp2\
,Proposed_Model/conv1d/BiasAdd/ReadVariableOp,Proposed_Model/conv1d/BiasAdd/ReadVariableOp2t
8Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOp8Proposed_Model/conv1d/conv1d/ExpandDims_1/ReadVariableOp:Y U
+
_output_shapes
:?????????
&
_user_specified_nameconv1d_input
?
?
'__inference_CONV_1_layer_call_fn_160730

inputs
unknown:(
	unknown_0:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallinputsunknown	unknown_0*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:?????????*$
_read_only_resource_inputs
*-
config_proto

CPU

GPU 2J 8? *K
fFRD
B__inference_CONV_1_layer_call_and_return_conditional_losses_1597142
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*+
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????(: : 22
StatefulPartitionedCallStatefulPartitionedCall:S O
+
_output_shapes
:?????????(
 
_user_specified_nameinputs
?
F
*__inference_DROPOUT_1_layer_call_fn_160839

inputs
identity?
PartitionedCallPartitionedCallinputs*
Tin
2*
Tout
2*
_collective_manager_ids
 *+
_output_shapes
:????????? * 
_read_only_resource_inputs
 *-
config_proto

CPU

GPU 2J 8? *N
fIRG
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_1597992
PartitionedCallp
IdentityIdentityPartitionedCall:output:0*
T0*+
_output_shapes
:????????? 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime**
_input_shapes
:????????? :S O
+
_output_shapes
:????????? 
 
_user_specified_nameinputs
?
?
__inference_loss_fn_1_160956K
5conv_2_kernel_regularizer_abs_readvariableop_resource:
identity??,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
,CONV_2/kernel/Regularizer/Abs/ReadVariableOpReadVariableOp5conv_2_kernel_regularizer_abs_readvariableop_resource*"
_output_shapes
:*
dtype02.
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp?
CONV_2/kernel/Regularizer/AbsAbs4CONV_2/kernel/Regularizer/Abs/ReadVariableOp:value:0*
T0*"
_output_shapes
:2
CONV_2/kernel/Regularizer/Abs?
CONV_2/kernel/Regularizer/ConstConst*
_output_shapes
:*
dtype0*!
valueB"          2!
CONV_2/kernel/Regularizer/Const?
CONV_2/kernel/Regularizer/SumSum!CONV_2/kernel/Regularizer/Abs:y:0(CONV_2/kernel/Regularizer/Const:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/Sum?
CONV_2/kernel/Regularizer/mul/xConst*
_output_shapes
: *
dtype0*
valueB
 *??82!
CONV_2/kernel/Regularizer/mul/x?
CONV_2/kernel/Regularizer/mulMul(CONV_2/kernel/Regularizer/mul/x:output:0&CONV_2/kernel/Regularizer/Sum:output:0*
T0*
_output_shapes
: 2
CONV_2/kernel/Regularizer/mul?
IdentityIdentity!CONV_2/kernel/Regularizer/mul:z:0-^CONV_2/kernel/Regularizer/Abs/ReadVariableOp*
T0*
_output_shapes
: 2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*
_input_shapes
: 2\
,CONV_2/kernel/Regularizer/Abs/ReadVariableOp,CONV_2/kernel/Regularizer/Abs/ReadVariableOp
?
?
/__inference_Proposed_Model_layer_call_fn_160189
conv1d_input
unknown:(
	unknown_0:(
	unknown_1:(
	unknown_2:
	unknown_3:
	unknown_4:
	unknown_5:
	unknown_6:
	unknown_7: 
	unknown_8: 
	unknown_9:	?@

unknown_10:@

unknown_11:@

unknown_12:
identity??StatefulPartitionedCall?
StatefulPartitionedCallStatefulPartitionedCallconv1d_inputunknown	unknown_0	unknown_1	unknown_2	unknown_3	unknown_4	unknown_5	unknown_6	unknown_7	unknown_8	unknown_9
unknown_10
unknown_11
unknown_12*
Tin
2*
Tout
2*
_collective_manager_ids
 *'
_output_shapes
:?????????*0
_read_only_resource_inputs
	
*-
config_proto

CPU

GPU 2J 8? *S
fNRL
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_1601252
StatefulPartitionedCall?
IdentityIdentity StatefulPartitionedCall:output:0^StatefulPartitionedCall*
T0*'
_output_shapes
:?????????2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*F
_input_shapes5
3:?????????: : : : : : : : : : : : : : 22
StatefulPartitionedCallStatefulPartitionedCall:Y U
+
_output_shapes
:?????????
&
_user_specified_nameconv1d_input
?
?
B__inference_CONV_3_layer_call_and_return_conditional_losses_159765

inputsA
+conv1d_expanddims_1_readvariableop_resource:-
biasadd_readvariableop_resource:
identity??BiasAdd/ReadVariableOp?"conv1d/ExpandDims_1/ReadVariableOpy
conv1d/ExpandDims/dimConst*
_output_shapes
: *
dtype0*
valueB :
?????????2
conv1d/ExpandDims/dim?
conv1d/ExpandDims
ExpandDimsinputsconv1d/ExpandDims/dim:output:0*
T0*/
_output_shapes
:?????????	2
conv1d/ExpandDims?
"conv1d/ExpandDims_1/ReadVariableOpReadVariableOp+conv1d_expanddims_1_readvariableop_resource*"
_output_shapes
:*
dtype02$
"conv1d/ExpandDims_1/ReadVariableOpt
conv1d/ExpandDims_1/dimConst*
_output_shapes
: *
dtype0*
value	B : 2
conv1d/ExpandDims_1/dim?
conv1d/ExpandDims_1
ExpandDims*conv1d/ExpandDims_1/ReadVariableOp:value:0 conv1d/ExpandDims_1/dim:output:0*
T0*&
_output_shapes
:2
conv1d/ExpandDims_1?
conv1dConv2Dconv1d/ExpandDims:output:0conv1d/ExpandDims_1:output:0*
T0*/
_output_shapes
:?????????	*
paddingSAME*
strides
2
conv1d?
conv1d/SqueezeSqueezeconv1d:output:0*
T0*+
_output_shapes
:?????????	*
squeeze_dims

?????????2
conv1d/Squeeze?
BiasAdd/ReadVariableOpReadVariableOpbiasadd_readvariableop_resource*
_output_shapes
:*
dtype02
BiasAdd/ReadVariableOp?
BiasAddBiasAddconv1d/Squeeze:output:0BiasAdd/ReadVariableOp:value:0*
T0*+
_output_shapes
:?????????	2	
BiasAdd\
ReluReluBiasAdd:output:0*
T0*+
_output_shapes
:?????????	2
Relu?
IdentityIdentityRelu:activations:0^BiasAdd/ReadVariableOp#^conv1d/ExpandDims_1/ReadVariableOp*
T0*+
_output_shapes
:?????????	2

Identity"
identityIdentity:output:0*(
_construction_contextkEagerRuntime*.
_input_shapes
:?????????	: : 20
BiasAdd/ReadVariableOpBiasAdd/ReadVariableOp2H
"conv1d/ExpandDims_1/ReadVariableOp"conv1d/ExpandDims_1/ReadVariableOp:S O
+
_output_shapes
:?????????	
 
_user_specified_nameinputs"?L
saver_filename:0StatefulPartitionedCall_1:0StatefulPartitionedCall_28"
saved_model_main_op

NoOp*>
__saved_model_init_op%#
__saved_model_init_op

NoOp*?
serving_default?
I
conv1d_input9
serving_default_conv1d_input:0?????????:
OUTPUT0
StatefulPartitionedCall:0?????????tensorflow/serving/predict:֒
?k
layer_with_weights-0
layer-0
layer_with_weights-1
layer-1
layer-2
layer_with_weights-2
layer-3
layer_with_weights-3
layer-4
layer_with_weights-4
layer-5
layer-6
layer-7
	layer-8

layer_with_weights-5

layer-9
layer-10
layer_with_weights-6
layer-11
	optimizer
regularization_losses
	variables
trainable_variables
	keras_api

signatures
+?&call_and_return_all_conditional_losses
?_default_save_signature
?__call__"?g
_tf_keras_sequential?g{"name": "Proposed_Model", "trainable": true, "expects_training_arg": true, "dtype": "float32", "batch_input_shape": null, "must_restore_from_config": false, "class_name": "Sequential", "config": {"name": "Proposed_Model", "layers": [{"class_name": "InputLayer", "config": {"batch_input_shape": {"class_name": "__tuple__", "items": [null, 20, 1]}, "dtype": "float32", "sparse": false, "ragged": false, "name": "conv1d_input"}}, {"class_name": "Conv1D", "config": {"name": "conv1d", "trainable": true, "batch_input_shape": {"class_name": "__tuple__", "items": [null, 20, 1]}, "dtype": "float32", "filters": 40, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "valid", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}, {"class_name": "Conv1D", "config": {"name": "CONV_1", "trainable": true, "dtype": "float32", "filters": 14, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}, {"class_name": "MaxPooling1D", "config": {"name": "POOLING_1", "trainable": true, "dtype": "float32", "strides": {"class_name": "__tuple__", "items": [2]}, "pool_size": {"class_name": "__tuple__", "items": [2]}, "padding": "valid", "data_format": "channels_last"}}, {"class_name": "Conv1D", "config": {"name": "CONV_2", "trainable": true, "dtype": "float32", "filters": 20, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}, {"class_name": "Conv1D", "config": {"name": "CONV_3", "trainable": true, "dtype": "float32", "filters": 26, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}, {"class_name": "Conv1D", "config": {"name": "CONV_4", "trainable": true, "dtype": "float32", "filters": 32, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}, {"class_name": "MaxPooling1D", "config": {"name": "POOLING_2", "trainable": true, "dtype": "float32", "strides": {"class_name": "__tuple__", "items": [2]}, "pool_size": {"class_name": "__tuple__", "items": [2]}, "padding": "valid", "data_format": "channels_last"}}, {"class_name": "Dropout", "config": {"name": "DROPOUT_1", "trainable": true, "dtype": "float32", "rate": 0.5, "noise_shape": null, "seed": null}}, {"class_name": "Flatten", "config": {"name": "FC", "trainable": true, "dtype": "float32", "data_format": "channels_last"}}, {"class_name": "Dense", "config": {"name": "DENSE_1", "trainable": true, "dtype": "float32", "units": 64, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}, {"class_name": "Dropout", "config": {"name": "DROPOUT_2", "trainable": true, "dtype": "float32", "rate": 0.5, "noise_shape": null, "seed": null}}, {"class_name": "Dense", "config": {"name": "OUTPUT", "trainable": true, "dtype": "float32", "units": 2, "activation": "softmax", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}}, "bias_initializer": {"class_name": "Zeros", "config": {}}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}}]}, "shared_object_id": 28, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 3, "axes": {"-1": 1}}, "shared_object_id": 29}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 20, 1]}, "is_graph_network": true, "save_spec": {"class_name": "TypeSpec", "type_spec": "tf.TensorSpec", "serialized": [{"class_name": "TensorShape", "items": [null, 20, 1]}, "float32", "conv1d_input"]}, "keras_version": "2.5.0", "backend": "tensorflow", "model_config": {"class_name": "Sequential", "config": {"name": "Proposed_Model", "layers": [{"class_name": "InputLayer", "config": {"batch_input_shape": {"class_name": "__tuple__", "items": [null, 20, 1]}, "dtype": "float32", "sparse": false, "ragged": false, "name": "conv1d_input"}, "shared_object_id": 0}, {"class_name": "Conv1D", "config": {"name": "conv1d", "trainable": true, "batch_input_shape": {"class_name": "__tuple__", "items": [null, 20, 1]}, "dtype": "float32", "filters": 40, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "valid", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 1}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 2}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 4}, {"class_name": "Conv1D", "config": {"name": "CONV_1", "trainable": true, "dtype": "float32", "filters": 14, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 5}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 6}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 7}, {"class_name": "MaxPooling1D", "config": {"name": "POOLING_1", "trainable": true, "dtype": "float32", "strides": {"class_name": "__tuple__", "items": [2]}, "pool_size": {"class_name": "__tuple__", "items": [2]}, "padding": "valid", "data_format": "channels_last"}, "shared_object_id": 8}, {"class_name": "Conv1D", "config": {"name": "CONV_2", "trainable": true, "dtype": "float32", "filters": 20, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 9}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 10}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 11}, {"class_name": "Conv1D", "config": {"name": "CONV_3", "trainable": true, "dtype": "float32", "filters": 26, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 12}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 13}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 14}, {"class_name": "Conv1D", "config": {"name": "CONV_4", "trainable": true, "dtype": "float32", "filters": 32, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 15}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 16}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 17}, {"class_name": "MaxPooling1D", "config": {"name": "POOLING_2", "trainable": true, "dtype": "float32", "strides": {"class_name": "__tuple__", "items": [2]}, "pool_size": {"class_name": "__tuple__", "items": [2]}, "padding": "valid", "data_format": "channels_last"}, "shared_object_id": 18}, {"class_name": "Dropout", "config": {"name": "DROPOUT_1", "trainable": true, "dtype": "float32", "rate": 0.5, "noise_shape": null, "seed": null}, "shared_object_id": 19}, {"class_name": "Flatten", "config": {"name": "FC", "trainable": true, "dtype": "float32", "data_format": "channels_last"}, "shared_object_id": 20}, {"class_name": "Dense", "config": {"name": "DENSE_1", "trainable": true, "dtype": "float32", "units": 64, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 21}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 22}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 23}, {"class_name": "Dropout", "config": {"name": "DROPOUT_2", "trainable": true, "dtype": "float32", "rate": 0.5, "noise_shape": null, "seed": null}, "shared_object_id": 24}, {"class_name": "Dense", "config": {"name": "OUTPUT", "trainable": true, "dtype": "float32", "units": 2, "activation": "softmax", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 25}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 26}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 27}]}}, "training_config": {"loss": "sparse_categorical_crossentropy", "metrics": [[{"class_name": "MeanMetricWrapper", "config": {"name": "accuracy", "dtype": "float32", "fn": "sparse_categorical_accuracy"}, "shared_object_id": 30}]], "weighted_metrics": null, "loss_weights": null, "optimizer_config": {"class_name": "Adam", "config": {"name": "Adam", "learning_rate": 0.0010000000474974513, "decay": 0.0, "beta_1": 0.8999999761581421, "beta_2": 0.9990000128746033, "epsilon": 1e-07, "amsgrad": false}}}}
?

kernel
bias
regularization_losses
	variables
trainable_variables
	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?

_tf_keras_layer?
{"name": "conv1d", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": {"class_name": "__tuple__", "items": [null, 20, 1]}, "stateful": false, "must_restore_from_config": false, "class_name": "Conv1D", "config": {"name": "conv1d", "trainable": true, "batch_input_shape": {"class_name": "__tuple__", "items": [null, 20, 1]}, "dtype": "float32", "filters": 40, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "valid", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 1}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 2}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 4, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 3, "axes": {"-1": 1}}, "shared_object_id": 29}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 20, 1]}}
?


kernel
bias
regularization_losses
	variables
trainable_variables
	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?	
_tf_keras_layer?{"name": "CONV_1", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Conv1D", "config": {"name": "CONV_1", "trainable": true, "dtype": "float32", "filters": 14, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 5}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 6}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 7, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 3, "axes": {"-1": 40}}, "shared_object_id": 31}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 18, 40]}}
?
regularization_losses
 	variables
!trainable_variables
"	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "POOLING_1", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "MaxPooling1D", "config": {"name": "POOLING_1", "trainable": true, "dtype": "float32", "strides": {"class_name": "__tuple__", "items": [2]}, "pool_size": {"class_name": "__tuple__", "items": [2]}, "padding": "valid", "data_format": "channels_last"}, "shared_object_id": 8, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": 3, "max_ndim": null, "min_ndim": null, "axes": {}}, "shared_object_id": 32}}
?

#kernel
$bias
%regularization_losses
&	variables
'trainable_variables
(	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?	
_tf_keras_layer?	{"name": "CONV_2", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Conv1D", "config": {"name": "CONV_2", "trainable": true, "dtype": "float32", "filters": 20, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 9}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 10}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 11, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 3, "axes": {"-1": 14}}, "shared_object_id": 33}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 9, 14]}}
?


)kernel
*bias
+regularization_losses
,	variables
-trainable_variables
.	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?	
_tf_keras_layer?	{"name": "CONV_3", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Conv1D", "config": {"name": "CONV_3", "trainable": true, "dtype": "float32", "filters": 26, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 12}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 13}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 14, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 3, "axes": {"-1": 20}}, "shared_object_id": 34}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 9, 20]}}
?


/kernel
0bias
1regularization_losses
2	variables
3trainable_variables
4	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?	
_tf_keras_layer?	{"name": "CONV_4", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Conv1D", "config": {"name": "CONV_4", "trainable": true, "dtype": "float32", "filters": 32, "kernel_size": {"class_name": "__tuple__", "items": [3]}, "strides": {"class_name": "__tuple__", "items": [1]}, "padding": "same", "data_format": "channels_last", "dilation_rate": {"class_name": "__tuple__", "items": [1]}, "groups": 1, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 15}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 16}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 17, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 3, "axes": {"-1": 26}}, "shared_object_id": 35}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 9, 26]}}
?
5regularization_losses
6	variables
7trainable_variables
8	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "POOLING_2", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "MaxPooling1D", "config": {"name": "POOLING_2", "trainable": true, "dtype": "float32", "strides": {"class_name": "__tuple__", "items": [2]}, "pool_size": {"class_name": "__tuple__", "items": [2]}, "padding": "valid", "data_format": "channels_last"}, "shared_object_id": 18, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": 3, "max_ndim": null, "min_ndim": null, "axes": {}}, "shared_object_id": 36}}
?
9regularization_losses
:	variables
;trainable_variables
<	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "DROPOUT_1", "trainable": true, "expects_training_arg": true, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Dropout", "config": {"name": "DROPOUT_1", "trainable": true, "dtype": "float32", "rate": 0.5, "noise_shape": null, "seed": null}, "shared_object_id": 19}
?
=regularization_losses
>	variables
?trainable_variables
@	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "FC", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Flatten", "config": {"name": "FC", "trainable": true, "dtype": "float32", "data_format": "channels_last"}, "shared_object_id": 20, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 1, "axes": {}}, "shared_object_id": 37}}
?	

Akernel
Bbias
Cregularization_losses
D	variables
Etrainable_variables
F	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "DENSE_1", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Dense", "config": {"name": "DENSE_1", "trainable": true, "dtype": "float32", "units": 64, "activation": "relu", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 21}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 22}, "kernel_regularizer": {"class_name": "L1", "config": {"l1": 9.999999747378752e-05}, "shared_object_id": 3}, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 23, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 2, "axes": {"-1": 128}}, "shared_object_id": 38}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 128]}}
?
Gregularization_losses
H	variables
Itrainable_variables
J	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "DROPOUT_2", "trainable": true, "expects_training_arg": true, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Dropout", "config": {"name": "DROPOUT_2", "trainable": true, "dtype": "float32", "rate": 0.5, "noise_shape": null, "seed": null}, "shared_object_id": 24}
?

Kkernel
Lbias
Mregularization_losses
N	variables
Otrainable_variables
P	keras_api
+?&call_and_return_all_conditional_losses
?__call__"?
_tf_keras_layer?{"name": "OUTPUT", "trainable": true, "expects_training_arg": false, "dtype": "float32", "batch_input_shape": null, "stateful": false, "must_restore_from_config": false, "class_name": "Dense", "config": {"name": "OUTPUT", "trainable": true, "dtype": "float32", "units": 2, "activation": "softmax", "use_bias": true, "kernel_initializer": {"class_name": "GlorotUniform", "config": {"seed": null}, "shared_object_id": 25}, "bias_initializer": {"class_name": "Zeros", "config": {}, "shared_object_id": 26}, "kernel_regularizer": null, "bias_regularizer": null, "activity_regularizer": null, "kernel_constraint": null, "bias_constraint": null}, "shared_object_id": 27, "input_spec": {"class_name": "InputSpec", "config": {"dtype": null, "shape": null, "ndim": null, "max_ndim": null, "min_ndim": 2, "axes": {"-1": 64}}, "shared_object_id": 39}, "build_input_shape": {"class_name": "TensorShape", "items": [null, 64]}}
?
Qiter

Rbeta_1

Sbeta_2
	Tdecay
Ulearning_ratem?m?m?m?#m?$m?)m?*m?/m?0m?Am?Bm?Km?Lm?v?v?v?v?#v?$v?)v?*v?/v?0v?Av?Bv?Kv?Lv?"
	optimizer
8
?0
?1
?2"
trackable_list_wrapper
?
0
1
2
3
#4
$5
)6
*7
/8
09
A10
B11
K12
L13"
trackable_list_wrapper
?
0
1
2
3
#4
$5
)6
*7
/8
09
A10
B11
K12
L13"
trackable_list_wrapper
?
Vlayer_metrics
regularization_losses
Wmetrics
Xnon_trainable_variables
Ylayer_regularization_losses
	variables

Zlayers
trainable_variables
?__call__
?_default_save_signature
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
-
?serving_default"
signature_map
#:!(2conv1d/kernel
:(2conv1d/bias
(
?0"
trackable_list_wrapper
.
0
1"
trackable_list_wrapper
.
0
1"
trackable_list_wrapper
?
[layer_metrics
regularization_losses
\metrics
]non_trainable_variables
^layer_regularization_losses
	variables

_layers
trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
#:!(2CONV_1/kernel
:2CONV_1/bias
 "
trackable_list_wrapper
.
0
1"
trackable_list_wrapper
.
0
1"
trackable_list_wrapper
?
`layer_metrics
regularization_losses
ametrics
bnon_trainable_variables
clayer_regularization_losses
	variables

dlayers
trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
?
elayer_metrics
regularization_losses
fmetrics
gnon_trainable_variables
hlayer_regularization_losses
 	variables

ilayers
!trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
#:!2CONV_2/kernel
:2CONV_2/bias
(
?0"
trackable_list_wrapper
.
#0
$1"
trackable_list_wrapper
.
#0
$1"
trackable_list_wrapper
?
jlayer_metrics
%regularization_losses
kmetrics
lnon_trainable_variables
mlayer_regularization_losses
&	variables

nlayers
'trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
#:!2CONV_3/kernel
:2CONV_3/bias
 "
trackable_list_wrapper
.
)0
*1"
trackable_list_wrapper
.
)0
*1"
trackable_list_wrapper
?
olayer_metrics
+regularization_losses
pmetrics
qnon_trainable_variables
rlayer_regularization_losses
,	variables

slayers
-trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
#:! 2CONV_4/kernel
: 2CONV_4/bias
 "
trackable_list_wrapper
.
/0
01"
trackable_list_wrapper
.
/0
01"
trackable_list_wrapper
?
tlayer_metrics
1regularization_losses
umetrics
vnon_trainable_variables
wlayer_regularization_losses
2	variables

xlayers
3trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
?
ylayer_metrics
5regularization_losses
zmetrics
{non_trainable_variables
|layer_regularization_losses
6	variables

}layers
7trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
?
~layer_metrics
9regularization_losses
metrics
?non_trainable_variables
 ?layer_regularization_losses
:	variables
?layers
;trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
?
?layer_metrics
=regularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
>	variables
?layers
?trainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
!:	?@2DENSE_1/kernel
:@2DENSE_1/bias
(
?0"
trackable_list_wrapper
.
A0
B1"
trackable_list_wrapper
.
A0
B1"
trackable_list_wrapper
?
?layer_metrics
Cregularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
D	variables
?layers
Etrainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
?
?layer_metrics
Gregularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
H	variables
?layers
Itrainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
:@2OUTPUT/kernel
:2OUTPUT/bias
 "
trackable_list_wrapper
.
K0
L1"
trackable_list_wrapper
.
K0
L1"
trackable_list_wrapper
?
?layer_metrics
Mregularization_losses
?metrics
?non_trainable_variables
 ?layer_regularization_losses
N	variables
?layers
Otrainable_variables
?__call__
+?&call_and_return_all_conditional_losses
'?"call_and_return_conditional_losses"
_generic_user_object
:	 (2	Adam/iter
: (2Adam/beta_1
: (2Adam/beta_2
: (2
Adam/decay
: (2Adam/learning_rate
 "
trackable_dict_wrapper
0
?0
?1"
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
v
0
1
2
3
4
5
6
7
	8

9
10
11"
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
(
?0"
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
(
?0"
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
(
?0"
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_dict_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
 "
trackable_list_wrapper
?

?total

?count
?	variables
?	keras_api"?
_tf_keras_metric?{"class_name": "Mean", "name": "loss", "dtype": "float32", "config": {"name": "loss", "dtype": "float32"}, "shared_object_id": 40}
?

?total

?count
?
_fn_kwargs
?	variables
?	keras_api"?
_tf_keras_metric?{"class_name": "MeanMetricWrapper", "name": "accuracy", "dtype": "float32", "config": {"name": "accuracy", "dtype": "float32", "fn": "sparse_categorical_accuracy"}, "shared_object_id": 30}
:  (2total
:  (2count
0
?0
?1"
trackable_list_wrapper
.
?	variables"
_generic_user_object
:  (2total
:  (2count
 "
trackable_dict_wrapper
0
?0
?1"
trackable_list_wrapper
.
?	variables"
_generic_user_object
(:&(2Adam/conv1d/kernel/m
:(2Adam/conv1d/bias/m
(:&(2Adam/CONV_1/kernel/m
:2Adam/CONV_1/bias/m
(:&2Adam/CONV_2/kernel/m
:2Adam/CONV_2/bias/m
(:&2Adam/CONV_3/kernel/m
:2Adam/CONV_3/bias/m
(:& 2Adam/CONV_4/kernel/m
: 2Adam/CONV_4/bias/m
&:$	?@2Adam/DENSE_1/kernel/m
:@2Adam/DENSE_1/bias/m
$:"@2Adam/OUTPUT/kernel/m
:2Adam/OUTPUT/bias/m
(:&(2Adam/conv1d/kernel/v
:(2Adam/conv1d/bias/v
(:&(2Adam/CONV_1/kernel/v
:2Adam/CONV_1/bias/v
(:&2Adam/CONV_2/kernel/v
:2Adam/CONV_2/bias/v
(:&2Adam/CONV_3/kernel/v
:2Adam/CONV_3/bias/v
(:& 2Adam/CONV_4/kernel/v
: 2Adam/CONV_4/bias/v
&:$	?@2Adam/DENSE_1/kernel/v
:@2Adam/DENSE_1/bias/v
$:"@2Adam/OUTPUT/kernel/v
:2Adam/OUTPUT/bias/v
?2?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160480
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160602
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160251
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160313?
???
FullArgSpec1
args)?&
jself
jinputs

jtraining
jmask
varargs
 
varkw
 
defaults?
p 

 

kwonlyargs? 
kwonlydefaults? 
annotations? *
 
?2?
!__inference__wrapped_model_159633?
???
FullArgSpec
args? 
varargsjargs
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? */?,
*?'
conv1d_input?????????
?2?
/__inference_Proposed_Model_layer_call_fn_159906
/__inference_Proposed_Model_layer_call_fn_160635
/__inference_Proposed_Model_layer_call_fn_160668
/__inference_Proposed_Model_layer_call_fn_160189?
???
FullArgSpec1
args)?&
jself
jinputs

jtraining
jmask
varargs
 
varkw
 
defaults?
p 

 

kwonlyargs? 
kwonlydefaults? 
annotations? *
 
?2?
B__inference_conv1d_layer_call_and_return_conditional_losses_160696?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
'__inference_conv1d_layer_call_fn_160705?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
B__inference_CONV_1_layer_call_and_return_conditional_losses_160721?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
'__inference_CONV_1_layer_call_fn_160730?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
E__inference_POOLING_1_layer_call_and_return_conditional_losses_159642?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *3?0
.?+'???????????????????????????
?2?
*__inference_POOLING_1_layer_call_fn_159648?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *3?0
.?+'???????????????????????????
?2?
B__inference_CONV_2_layer_call_and_return_conditional_losses_160758?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
'__inference_CONV_2_layer_call_fn_160767?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
B__inference_CONV_3_layer_call_and_return_conditional_losses_160783?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
'__inference_CONV_3_layer_call_fn_160792?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
B__inference_CONV_4_layer_call_and_return_conditional_losses_160808?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
'__inference_CONV_4_layer_call_fn_160817?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
E__inference_POOLING_2_layer_call_and_return_conditional_losses_159657?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *3?0
.?+'???????????????????????????
?2?
*__inference_POOLING_2_layer_call_fn_159663?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *3?0
.?+'???????????????????????????
?2?
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_160822
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_160834?
???
FullArgSpec)
args!?
jself
jinputs

jtraining
varargs
 
varkw
 
defaults?
p 

kwonlyargs? 
kwonlydefaults? 
annotations? *
 
?2?
*__inference_DROPOUT_1_layer_call_fn_160839
*__inference_DROPOUT_1_layer_call_fn_160844?
???
FullArgSpec)
args!?
jself
jinputs

jtraining
varargs
 
varkw
 
defaults?
p 

kwonlyargs? 
kwonlydefaults? 
annotations? *
 
?2?
>__inference_FC_layer_call_and_return_conditional_losses_160850?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
#__inference_FC_layer_call_fn_160855?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
C__inference_DENSE_1_layer_call_and_return_conditional_losses_160878?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
(__inference_DENSE_1_layer_call_fn_160887?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_160892
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_160904?
???
FullArgSpec)
args!?
jself
jinputs

jtraining
varargs
 
varkw
 
defaults?
p 

kwonlyargs? 
kwonlydefaults? 
annotations? *
 
?2?
*__inference_DROPOUT_2_layer_call_fn_160909
*__inference_DROPOUT_2_layer_call_fn_160914?
???
FullArgSpec)
args!?
jself
jinputs

jtraining
varargs
 
varkw
 
defaults?
p 

kwonlyargs? 
kwonlydefaults? 
annotations? *
 
?2?
B__inference_OUTPUT_layer_call_and_return_conditional_losses_160925?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
'__inference_OUTPUT_layer_call_fn_160934?
???
FullArgSpec
args?
jself
jinputs
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 
?2?
__inference_loss_fn_0_160945?
???
FullArgSpec
args? 
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *? 
?2?
__inference_loss_fn_1_160956?
???
FullArgSpec
args? 
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *? 
?2?
__inference_loss_fn_2_160967?
???
FullArgSpec
args? 
varargs
 
varkw
 
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *? 
?B?
$__inference_signature_wrapper_160372conv1d_input"?
???
FullArgSpec
args? 
varargs
 
varkwjkwargs
defaults
 

kwonlyargs? 
kwonlydefaults
 
annotations? *
 ?
B__inference_CONV_1_layer_call_and_return_conditional_losses_160721d3?0
)?&
$?!
inputs?????????(
? ")?&
?
0?????????
? ?
'__inference_CONV_1_layer_call_fn_160730W3?0
)?&
$?!
inputs?????????(
? "???????????
B__inference_CONV_2_layer_call_and_return_conditional_losses_160758d#$3?0
)?&
$?!
inputs?????????	
? ")?&
?
0?????????	
? ?
'__inference_CONV_2_layer_call_fn_160767W#$3?0
)?&
$?!
inputs?????????	
? "??????????	?
B__inference_CONV_3_layer_call_and_return_conditional_losses_160783d)*3?0
)?&
$?!
inputs?????????	
? ")?&
?
0?????????	
? ?
'__inference_CONV_3_layer_call_fn_160792W)*3?0
)?&
$?!
inputs?????????	
? "??????????	?
B__inference_CONV_4_layer_call_and_return_conditional_losses_160808d/03?0
)?&
$?!
inputs?????????	
? ")?&
?
0?????????	 
? ?
'__inference_CONV_4_layer_call_fn_160817W/03?0
)?&
$?!
inputs?????????	
? "??????????	 ?
C__inference_DENSE_1_layer_call_and_return_conditional_losses_160878]AB0?-
&?#
!?
inputs??????????
? "%?"
?
0?????????@
? |
(__inference_DENSE_1_layer_call_fn_160887PAB0?-
&?#
!?
inputs??????????
? "??????????@?
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_160822d7?4
-?*
$?!
inputs????????? 
p 
? ")?&
?
0????????? 
? ?
E__inference_DROPOUT_1_layer_call_and_return_conditional_losses_160834d7?4
-?*
$?!
inputs????????? 
p
? ")?&
?
0????????? 
? ?
*__inference_DROPOUT_1_layer_call_fn_160839W7?4
-?*
$?!
inputs????????? 
p 
? "?????????? ?
*__inference_DROPOUT_1_layer_call_fn_160844W7?4
-?*
$?!
inputs????????? 
p
? "?????????? ?
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_160892\3?0
)?&
 ?
inputs?????????@
p 
? "%?"
?
0?????????@
? ?
E__inference_DROPOUT_2_layer_call_and_return_conditional_losses_160904\3?0
)?&
 ?
inputs?????????@
p
? "%?"
?
0?????????@
? }
*__inference_DROPOUT_2_layer_call_fn_160909O3?0
)?&
 ?
inputs?????????@
p 
? "??????????@}
*__inference_DROPOUT_2_layer_call_fn_160914O3?0
)?&
 ?
inputs?????????@
p
? "??????????@?
>__inference_FC_layer_call_and_return_conditional_losses_160850]3?0
)?&
$?!
inputs????????? 
? "&?#
?
0??????????
? w
#__inference_FC_layer_call_fn_160855P3?0
)?&
$?!
inputs????????? 
? "????????????
B__inference_OUTPUT_layer_call_and_return_conditional_losses_160925\KL/?,
%?"
 ?
inputs?????????@
? "%?"
?
0?????????
? z
'__inference_OUTPUT_layer_call_fn_160934OKL/?,
%?"
 ?
inputs?????????@
? "???????????
E__inference_POOLING_1_layer_call_and_return_conditional_losses_159642?E?B
;?8
6?3
inputs'???????????????????????????
? ";?8
1?.
0'???????????????????????????
? ?
*__inference_POOLING_1_layer_call_fn_159648wE?B
;?8
6?3
inputs'???????????????????????????
? ".?+'????????????????????????????
E__inference_POOLING_2_layer_call_and_return_conditional_losses_159657?E?B
;?8
6?3
inputs'???????????????????????????
? ";?8
1?.
0'???????????????????????????
? ?
*__inference_POOLING_2_layer_call_fn_159663wE?B
;?8
6?3
inputs'???????????????????????????
? ".?+'????????????????????????????
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160251z#$)*/0ABKLA?>
7?4
*?'
conv1d_input?????????
p 

 
? "%?"
?
0?????????
? ?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160313z#$)*/0ABKLA?>
7?4
*?'
conv1d_input?????????
p

 
? "%?"
?
0?????????
? ?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160480t#$)*/0ABKL;?8
1?.
$?!
inputs?????????
p 

 
? "%?"
?
0?????????
? ?
J__inference_Proposed_Model_layer_call_and_return_conditional_losses_160602t#$)*/0ABKL;?8
1?.
$?!
inputs?????????
p

 
? "%?"
?
0?????????
? ?
/__inference_Proposed_Model_layer_call_fn_159906m#$)*/0ABKLA?>
7?4
*?'
conv1d_input?????????
p 

 
? "???????????
/__inference_Proposed_Model_layer_call_fn_160189m#$)*/0ABKLA?>
7?4
*?'
conv1d_input?????????
p

 
? "???????????
/__inference_Proposed_Model_layer_call_fn_160635g#$)*/0ABKL;?8
1?.
$?!
inputs?????????
p 

 
? "???????????
/__inference_Proposed_Model_layer_call_fn_160668g#$)*/0ABKL;?8
1?.
$?!
inputs?????????
p

 
? "???????????
!__inference__wrapped_model_159633|#$)*/0ABKL9?6
/?,
*?'
conv1d_input?????????
? "/?,
*
OUTPUT ?
OUTPUT??????????
B__inference_conv1d_layer_call_and_return_conditional_losses_160696d3?0
)?&
$?!
inputs?????????
? ")?&
?
0?????????(
? ?
'__inference_conv1d_layer_call_fn_160705W3?0
)?&
$?!
inputs?????????
? "??????????(;
__inference_loss_fn_0_160945?

? 
? "? ;
__inference_loss_fn_1_160956#?

? 
? "? ;
__inference_loss_fn_2_160967A?

? 
? "? ?
$__inference_signature_wrapper_160372?#$)*/0ABKLI?F
? 
??<
:
conv1d_input*?'
conv1d_input?????????"/?,
*
OUTPUT ?
OUTPUT?????????