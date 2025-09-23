[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/E6j2spNg)
# FastAPI 세미나 과제 2

본 과제에서는 세미나에서 다룬 내용에 대한 추가 조사 및 응용을 요구합니다.  
과제 수행 과정에서 적극적으로 공식 문서를 찾아보고, 질문해보시기를 권유드립니다.  

## 과제 목표

- Token-Based Authentication과 Session-Based Authentication 방식을 모두 구현할 수 있다.
- JWT 토큰을 생성하고 검증할 수 있다.
- 의존성 주입을 활용하여 API를 구현할 수 있다.  
- EC2를 활용해 FastAPI 서버를 배포할 수 있다.

## 준비 사항

- 이번 과제는 저번 회차 과제와 이어집니다.

- 이번 과제는 저번 회차 과제와 마찬가지로 `python 3.12` 버전을 기준으로 하며, `uv`를 이용해 패키지를 관리합니다.
	- `uv venv` 명령어로 가상환경을 생성하고,
	- `uv sync` 명령어로 `uv.lock` 파일에 기본 제공된 라이브러리를 설치해주세요.

- 이번 과제는 저번 회차 과제와 달리, **서드파티 라이브러리 추가를 허용**합니다.
	- `pip install` 대신 `uv add`를 이용해 서드파티 라이브러리를 설치하시면 됩니다.
	- `uv add`를 이용해 설치하시면 `pyproject.toml` 파일과 `uv.lock` 파일의 내용이 수정되는데, **이 또한 함께 commit해주셔야 합니다**.
		- 그렇지 않으면 활용하신 라이브러리를 알 수 없어, 과제 채점에 차질이 생길 수 있습니다.

- `uv` 설치 및 사용에 관한 구체적인 내용은 [`uv` 공식문서](https://docs.astral.sh/uv/)를 참조하세요.

## 과제 요구 사항

### 개요
- 사용자의 회원 정보를 관리하는 API를 구현합니다.  
- 사용자에 대한 인증 및 인가 API를 구현합니다.  
	-  Session-Based Authentication 방식과 Token-Based Authentication 방식을 모두 구현합니다.
- 제공된 스켈레톤 코드에 얽매일 필요는 없으며, 필요에 따라 파일, 함수 등을 추가 또는 제거하셔도 좋습니다.  


### 1. `/api/users` 엔드포인트

#### 1-1) POST /api/users — 회원 가입

- 저번 과제에서 이어지는 내용입니다.
- 사용자의 회원 가입 요청을 받아 검증 및 처리하며, 성공 시 `user_db`(list[User])에 저장합니다.

- 회원 가입 요청이 들어오면 다음의 사항이 검증돼야 합니다.
	- 필요한 value가 모두 있어야 합니다.
	- 각 value의 자료형이 적합해야 합니다.
	- `email`: 기존에 존재하는 회원과 중복되지 않는지 확인해야 합니다.
	- `password`: 8자 이상 20자 이하여야 합니다.
	- `phone_number`: 010-XXXX-XXXX 형식이어야 합니다.
	- `bio`: 최대 500자여야 합니다.
- 회원 가입 성공 시 다음과 같이 정보를 저장해야 합니다.
	- 데이터베이스를 아직 배우지 않았기 때문에, 이번 과제에서는 전역 변수인 `user_db`(list[User])에 데이터를 관리합니다.
	- 사용자 저장소(`user_db`: list[User])
		- `User`(dict|BaseModel)의 구성 항목
			- `user_id` (int): 필수. 서버에서 사용자에게 임의로 부여하는 고유 식별자
			- `email` (str): 필수
			- `hashed_password` (str): 필수. 단방향 암호화된 형태로 저장돼야 합니다.
			- `name` (str): 필수
			- `phone_number` (str): 필수
			- `height` (float): 필수
			- `bio` (str): 선택. 최대 500자

		- 예시
			```json
			[
				{
					"user_id": 1,
					"email": "waffle@example.com",
					"hashed_password": "$argon2id$v=19$m=65536,t=3,p=4$...",
					"name": "김와플",
					"phone_number": "010-1234-5678",
					"height": 175.5,
					"bio": "안녕하세요"
				},
				...
			]
			```

- **요청**
	- 본문 예시
		```json
		{
			"email": "waffle@example.com",
			"password": "password1234",
			"name": "김와플",
			"phone_number": "010-1234-5678",
			"height": 175.5,
			"bio": "안녕하세요"
		}
		```


- **응답**
	- **성공 응답**
		- 상태 코드: 201
		- 본문: 다음의 항목으로 구성된 JSON 
			- `user_id`(int, 필수)
			- `email` (str, 필수)
			- `name` (str, 필수)
			- `phone_number` (str, 필수)
			- `height` (float, 필수)
			- `bio` (str, 선택)
		- 예시  
			상태 코드 201과 함께 본문으로 다음의 JSON이 반환됨.
			```json
			{
				"user_id": 1,
				"email": "waffle@example.com",
				"name": "김와플",
				"phone_number": "010-1234-5678",
				"height": 175.5,
				"bio": "안녕하세요"
			}
			```

	- **실패 응답**
		|   상황|상태 코드|ERROR_CODE|ERROR_MSG|
		|-------|--------|---------|---------|
		|요청 본문에서 필수값이 누락된 경우|422|ERR_001|MISSING VALUE|
		|`password`의 검증에 실패한 경우|422|ERR_002|INVALID PASSWORD|
		|`phone_number`의 검증에 실패한 경우|422|ERR_003|INVALID PHONE NUMBER|
		|`bio`의 길이가 초과한 경우|422|ERR_004|BIO TOO LONG|
		|같은 이메일의 사용자가 DB에 이미 등록되어 있는 경우|409|ERR_005|EMAIL ALREADY EXISTS|
		- 예시  
			상태 코드 422와 함께 다음의 본문(application/json)이 반환됨.
			```json
			{
				"error_code": "ERR_001",
				"error_msg": "MISSING VALUE"
			}
			```
		
		

#### 1-2) GET /api/users/me — 내 정보 조회
- 서버는 다음의 방식으로 사용자의 신분 증명을 검증한 후, 사용자가 식별되면 해당 사용자의 정보를 응답 본문으로 보냅니다.
	- Session-based authentication
		- 요청에 `sid` 쿠키가 있는지 확인합니다.
		- 해당 `sid`를 가진 세션이 존재하는지 확인합니다.
		- 해당 세션이 만료되지 않았는지 확인합니다.
		- 해당 세션 사용자의 정보를 반환합니다.
	- Token-based authentication
		- 요청 헤더에 `Authorization` 필드가 있는지 확인합니다.
		- 해당 헤더의 값이 `Bearer access_token`의 형식인지 확인합니다.
		- `access_token`을 decode합니다.
		- `access_token`이 위조, 변조되지 않았는지 검증합니다.
		- `access_token`이 만료되지 않았는지 확인합니다.
		- `access_token`의 `sub` claim에 대응되는 사용자의 정보를 반환합니다.
	- 한 번의 요청에 위 두 신분 증명이 모두 있는 경우는 고려하지 않아도 됩니다.
- 처리 결과에 따라 다음와 같이 응답합니다.
	- **성공 응답**
		- `POST /api/users`의 성공 응답과 동일합니다(단, 상태 코드는 200).
	- **실패 응답**
		|   상황|상태 코드|ERROR_CODE|ERROR_MSG|
		|-------|--------|---------|---------|
		|유효하지 않은 세션인 경우|401|ERR_006|INVALID SESSION|
		|Authorization 헤더 값의 형식이 비정상적인 경우|400|ERR_007|BAD AUTHORIZATION HEADER|
		|Authorization 헤더 값의 형식은 정상적이나 토큰이 유효하지 않은 경우|401|ERR_008|INVALID TOKEN|
		|유효한 신분 증명 없이 요청한 경우|401|ERR_009|UNAUTHENTICATED|



### 2. `/auth/token` 엔드포인트(Token-Based Authentication)

#### 2-1) POST /auth/token — 로그인 및 토큰 발급

- 서버가 사용자 인증에 성공하면, Access/Refresh Token을 발급하여 반환합니다.
- Access/Refresh Token은 다음과 같이 구성됩니다.
	- 다음의 claim으로 구성된 JWT 토큰이어야 합니다
		- `sub`: 토큰 주체를 구분하기 위한 고유 식별자
		- `exp`
			- Access Token의 경우 `SHORT_SESSION_LIFESPAN`(분) 동안 유효한 것으로 합니다.
			- Refresh Token의 경우 `LONG_SESSION_LIFESPAN`(분) 동안 유효한 것으로 합니다.
- **요청**
	- 요청 예시
		```json
		{
			"email": "waffle@example.com",
			"password": "password1234"
		}
		```
- **응답**
	- 성공 응답
		- 코드: 200
		- 본문
			- 다음의 항목으로 구성된 JSON:  `access_token`, `refresh_token`
		- 예시
			```json
			{
				"access_token": "eyJhbGciOi...",
				"refresh_token": "eyJhbGciOi..."
			}
			```

	- 실패 응답
		|   상황|상태 코드|ERROR_CODE|ERROR_MSG|
		|-------|--------|---------|---------|
		|요청 본문에서 필수값이 누락된 경우|422|ERR_001|MISSING VALUE|
		|이메일이 `user_db`에 존재하지 않거나, 비밀번호가 올바르지 않은 경우|401|ERR_010|INVALID ACCOUNT|


#### 2-2) POST /auth/token/refresh — 토큰 갱신

- `refresh_token`을 검증하고, 새 `access_token`과 `refresh_token`을 재발급합니다.
- 검증 방법은 `1-2)`와 동일합니다.
- 이때 `refresh_token`이 블랙리스트(`blocked_token_db`: dict)에 있는지 확인해야 합니다.
- 새로 발급된 `refresh_token`은 기존 토큰과 교체되어야 하므로, 기존 토큰은 `blocked_token_db`에 추가합니다.
- 이 때, `refresh_token`은 `토큰 원문`을 `key`, `토큰의 원래 만료 시점`을 `value`로 하여 `blocked_token_db`에 추가합니다.
- 각 토큰의 구성 방법은 `POST /auth/token`과 동일합니다.

##### 요청 예시
- 다음의 Field가 헤더에 포함됨
	```
	Authorization: Bearer refresh_token(JWT)값
	```


##### 응답
- 성공 응답: `POST /auth/token과 동일`

- 실패 응답  
	|   상황|상태 코드|ERROR_CODE|ERROR_MSG|
	|-------|--------|---------|---------|
	|Authorization 헤더 값의 형식이 비정상적인 경우|400|ERR_007|BAD AUTHORIZATION HEADER|
	|Authorization 헤더 값의 형식은 정상적이나 토큰이 유효하지 않은 경우|401|ERR_008|INVALID TOKEN|
	|Authorization 헤더가 제시되지 않은 경우|401|ERR_009|UNAUTHENTICATED|


#### 2-3) DELETE /auth/token — 토큰 무효화(로그아웃)

- 사용자의 `refresh_token`을 무효화합니다.
- 블랙리스트(`blocked_token_db`)에 저장하여 추후 재사용을 방지합니다.
- 블랙리스트에 저장할 때는 `토큰 원문`을 `key`, `토큰의 원래 만료 시점`을 `value`로 하여 저장합니다.

##### 요청 예시
- 다음의 Field가 헤더에 포함됨
	```
	Authorization: Bearer refresh_token(JWT)값
	```

##### 응답
- 성공 응답: 상태 코드 `204`
- 실패 응답
	|상황|상태 코드|ERROR_CODE|ERROR_MSG|
	|-------|--------|---------|---------|
	|Authorization 헤더 값의 형식이 비정상적인 경우|400|ERR_007|BAD AUTHORIZATION HEADER|
	|Authorization 헤더 값의 형식은 정상적이나 토큰이 유효하지 않은 경우|401|ERR_008|INVALID TOKEN|
	|Authorization 헤더가 제시되지 않은 경우|401|ERR_009|UNAUTHENTICATED|




## 3. 세션 기반 인증 API

### 3-1) POST /auth/session — 세션 로그인
- 서버는 `email`과 `password`로 사용자를 검증하고, 이에 성공하면 세션을 생성 및 저장합니다.
- 서버는 생성한 `sid`(str)를 클라이언트의 쿠키로 설정합니다.
	- 세션은 `LONG_SESSION_LIFESPAN`(분) 동안 유효한 것으로 합니다.
- **요청 예시**
	```json
	{
		"email": "waffle@example.com",
		"password": "password1234"
	}
	```

- **응답**
	- 성공 응답
		- 코드: `200`
		- 클라이언트의 쿠키에 `sid`를 추가하기 위한 적절한 헤더를 포함해야 합니다.
	- 실패 응답
		|상황|상태 코드|ERROR_CODE|ERROR_MSG|
		|-------|--------|---------|---------|
		|요청 본문에서 필수값이 누락된 경우|422|ERR_001|MISSING VALUE|
		|이메일이 `user_db`에 존재하지 않거나, 비밀번호가 올바르지 않은 경우|401|ERR_010|INVALID ACCOUNT|

### 3-2) DELETE /auth/session — 세션 로그아웃
- 요청의 쿠키 중 이름이 `sid`인 것이 있는지 확인합니다.
	- 존재하는 경우
		- 클라이언트의 `sid` 쿠키를 만료시켜야 합니다.
		- 해당 `sid`를 가진 세션이 존재하는지 확인합니다.
			- 존재하는 경우, 서버에 저장되어 있는 세션 정보를 제거합니다.
			- 존재하지 않는 경우, 서버에 저장되어 있는 세션 정보에 대해서는 별도의 작업을 하지 않습니다.
	- 존재하지 않는 경우, 본문 없는 응답을 반환합니다.

- 응답의 상태 코드는 모두 `204`로 통일합니다.



## 제출 방법

- 이번 과제는 **소스 코드**와 함께 **해당 코드로 가동된 EC2 서버의 IP 주소**까지 기한 안으로 제출해주셔야 완료됩니다!
- 과제 수락 시 생성된 repository의 `main` 브랜치에 소스 코드와 EC2 서버의 IP 주소를 담아 push해주세요.
- IP 주소는 프로젝트 루트 폴더의 **server_ip.py를 수정**하는 방식으로 제출해주세요.  
- 완성된 코드는 **프로젝트 루트 디렉토리에서 `uv run uvicorn src.main:app` 명령어 실행으로 서버가 가동되어야 합니다**.  

- 테스트 케이스는 제출하신 IP 주소의 실제 서버에서 작동시킬 예정입니다. 따라서 최종 제출 코드를 EC2 서버 상에 반드시 반영해주세요.  

- **(주의⚠️) Feedback PR 은 머지하지 마세요!!**

