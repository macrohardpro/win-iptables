#include "gtest/gtest.h"
#include <iostream>
#include <string>

int add(int a, int b)
{
	return a + b;
}

TEST(add, negative)
{
	EXPECT_EQ(-3, add(-2, -1));
	EXPECT_EQ(-2, add(1, -3));
}

TEST(add, positive)
{
	EXPECT_EQ(1, add(2, -1));
	EXPECT_EQ(2, add(-1, 3));
}

TEST(add, limit)
{
	int a = 0x7fffffff + 1;
	std::cout << "a = " << a << "\n";
	EXPECT_EQ(a, add(0x7fffffff, 1));
	EXPECT_EQ(0, add(0xffffffff, 1));
}

int main(int argc, char** argv) {

	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();

	return 0;
}