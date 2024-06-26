/*****************************************************************************
** Copyright (C) 2016 Open-TEE project.                                     **
** Copyright (C) 2016 Atte Pellikka                                         **
** Copyright (C) 2016 Brian McGillion                                       **
** Copyright (C) 2016 Tanel Dettenborn                                      **
** Copyright (C) 2016 Ville Kankainen                                       **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#ifdef TA_PLUGIN

#include "tee_ta_properties.h"

/* Setting TA properties */
SET_TA_PROPERTIES(
	{ 0xfd02c9da, 0x306c, 0x48c7, \
			 { 0xa4, 0x9c, 0xbb, 0xd8, 0x27, 0xae, 0x86, 0xee } }, /* UUID */
	//{ 0x12345678, 0x8765, 0x4321, { 'O', 'P', 'T', 'E', 'E'} }, /* UUID */
		512, /* dataSize */
		8192, /* stackSize */
		1, /* singletonInstance */
		1, /* multiSession */
		0) /* instanceKeepAlive */

#endif // TA_PLUGIN

// 0x12345678, 0x8765, 0x4321, { 'O', 'P', 'T', 'E', 'E', 'P', 'K', 'C', 'S', '1', '1', 'T', 'A'}