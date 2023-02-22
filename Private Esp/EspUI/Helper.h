#pragma once

#include "D3D11Renderer.h"

static HMODULE GetD3DCompiler()
{
	char buf[32];
	for (int i = 50; i >= 30; i--)
	{
		sprintf_s(buf, "D3DCompiler_%d.dll", i);
		HMODULE mod = LoadLibrary(buf);
		if (mod)
			return mod;
	}

	return NULL;
}

template<class T> inline void SAFE_DELETE(T*& p)
{
	if (p)
	{s
		delete p;
		p = NULL;
	}
}

template<class T> inline void SAFE_DELETE_ARRAY(T*& p)
{
	if (p)
	{
		delete[] p;
		p = NULL;
	}
}

template<class T> inline void SAFE_RELEASE(T*& p)
{
	if (p)
	{
		p->Release();
		p = NULL;
	}
}

struct FMinimalViewInfo
{
	Vector3 Location; //+ 0x1260
	Vector3 Rotation; //+ 0x126C
	float FOV;     //+ 0x1278
};

class FRotator
{
public:
	float Pitch = 0.f;
	float Yaw = 0.f;
	float Roll = 0.f;

	D3DMATRIX GetAxes() {
		auto tempMatrix = Matrix();
		return tempMatrix;
	}

	D3DMATRIX Matrix(Vector3 origin = Vector3(0, 0, 0)) {
		float radPitch = (Pitch * float(UCONST_Pi) / 180.f);
		float radYaw = (Yaw * float(UCONST_Pi) / 180.f);
		float radRoll = (Roll * float(UCONST_Pi) / 180.f);
		float SP = sinf(radPitch);
		float CP = cosf(radPitch);
		float SY = sinf(radYaw);
		float CY = cosf(radYaw);
		float SR = sinf(radRoll);
		float CR = cosf(radRoll);

		D3DMATRIX matrix;
		matrix.m[0][0] = CP * CY;
		matrix.m[0][1] = CP * SY;
		matrix.m[0][2] = SP;
		matrix.m[0][3] = 0.f;

		matrix.m[1][0] = SR * SP * CY - CR * SY;
		matrix.m[1][1] = SR * SP * SY + CR * CY;
		matrix.m[1][2] = -SR * CP;
		matrix.m[1][3] = 0.f;

		matrix.m[2][0] = -(CR * SP * CY + SR * SY);
		matrix.m[2][1] = CY * SR - CR * SP * SY;
		matrix.m[2][2] = CR * CP;
		matrix.m[2][3] = 0.f;

		matrix.m[3][0] = origin.x;
		matrix.m[3][1] = origin.y;
		matrix.m[3][2] = origin.z;
		matrix.m[3][3] = 1.f;

		return matrix;
	}
};
#endif


