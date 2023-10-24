
#define MAO_HEADROOM_OVERALLOC_COW_SIZE_FOR_LINK_LAYER 20

inline unsigned short mao_ntohs_htons(char * firstP)
{
	unsigned short ret;
	*((char*)(&ret)) = firstP[1];
	*(((char*)(&ret))+1) = firstP[0];
	return ret;
}

inline unsigned int mao_ntohl_htonl(char * firstP)
{
	//no use
	unsigned int ret;
	*((char*)(&ret)) = firstP[3];
	*(((char*)(&ret))+1) = firstP[2];
	*(((char*)(&ret))+2) = firstP[1];
	*(((char*)(&ret))+3) = firstP[0];
	return ret;
}

inline unsigned short mao_ntohs_htons_val(unsigned short val)
{
	return mao_ntohs_htons((char*)(&val));
}

inline unsigned int mao_ntohl_htonl_val(unsigned int val)
{
	return mao_ntohl_htonl((char*)(&val));
}

#define m2s(firstP) mao_ntohs_htons((char*)(firstP))
#define m2sv(us) mao_ntohs_htons_val(us)
#define m2l(firstP) mao_ntohl_htonl((char*)(firstP))
#define m2lv(ul) mao_ntohl_htonl_val(ul)

























